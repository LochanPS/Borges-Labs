package bundle

import (
	"context"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// SimSource is the read side the simulator needs (a published version, or the working
// copy). Satisfied by *policyctl.PostgresStore and *policyctl.MemStore.
type SimSource interface {
	GetPolicy(ctx context.Context, orgID, id string) (*policyctl.Policy, error)
	GetVersion(ctx context.Context, orgID, policyID, versionHash string) (*policyctl.Version, error)
}

// Simulator dry-runs a policy against a batch of requests and returns what it WOULD
// have decided (ROADMAP Task 2.3 — the "what would this policy have done last week"
// demo). Results are UNSIGNED and marked shadow: a simulation is never enforceable and
// nothing is persisted to the audit log.
type Simulator struct {
	src SimSource
	now func() time.Time
}

// NewSimulator builds a simulator over the control-plane store.
func NewSimulator(src SimSource) *Simulator {
	return &Simulator{src: src, now: func() time.Time { return time.Now().UTC() }}
}

// Simulate evaluates each request against a target policy version. When versionHash is
// given, that immutable published version is used; otherwise the policy's current
// working copy (draft) is validated and used, so an author can preview edits before
// publishing. It returns the version label that was evaluated and one would-be decision
// per request, in order. A request's own evaluated_at is honored (replaying historical
// traffic); absent, the current time is stamped.
func (s *Simulator) Simulate(ctx context.Context, orgID, policyID, versionHash string, reqs []contractsv1.AuthorizeRequest) (string, []contractsv1.Decision, error) {
	var (
		pol   engine.Policy
		label string
		err   error
	)
	if versionHash != "" {
		var v *policyctl.Version
		if v, err = s.src.GetVersion(ctx, orgID, policyID, versionHash); err != nil {
			return "", nil, err
		}
		if pol, err = Compile(v); err != nil {
			return "", nil, err
		}
		label = v.VersionHash
	} else {
		var p *policyctl.Policy
		if p, err = s.src.GetPolicy(ctx, orgID, policyID); err != nil {
			return "", nil, err
		}
		// The draft must be publishable to simulate it (same gate as publish), so a
		// preview never reports verdicts a real publish would reject.
		if verr := policyctl.Validate(p.OrgID, p.Name, p.Agents, p.Rules); verr != nil {
			return "", nil, verr
		}
		label = "draft:" + p.ID
		if pol, err = CompileRules(label, p.Rules); err != nil {
			return "", nil, err
		}
	}

	out := make([]contractsv1.Decision, 0, len(reqs))
	for _, req := range reqs {
		evaluatedAt := req.EvaluatedAt
		if evaluatedAt == "" {
			evaluatedAt = s.now().Format(time.RFC3339)
		}
		d := engine.Evaluate(pol, req, evaluatedAt)
		d.Shadow = true // a simulation is advisory by construction; never enforceable
		out = append(out, d)
	}
	return label, out, nil
}

// The concrete stores satisfy SimSource at compile time.
var (
	_ SimSource = (*policyctl.MemStore)(nil)
	_ SimSource = (*policyctl.PostgresStore)(nil)
)

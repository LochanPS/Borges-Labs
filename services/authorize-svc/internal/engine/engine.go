package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	"github.com/trust-infra/authorize-svc/internal/ulid"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// ErrNoActiveBundle is returned by a BundleProvider when an org has no published
// bundle. It lives here (not in internal/bundle) so the engine can recognize it
// without importing the control plane; internal/bundle returns this exact value.
var ErrNoActiveBundle = errors.New("engine: no active bundle for org")

// Policy is an in-memory, immutable set of predicates the engine evaluates, plus any
// budget declarations that apply. Version is the policy_version_hash every decision
// cites. Predicates are the LOCAL rules evaluated here; Budgets are stateful rules
// (rolling_budget) that are NOT evaluated locally (ROADMAP A#3) — in Phase 3.1 their
// presence marks a decision budget-affecting (a hold is placed); Phase 3.2 adds the
// atomic counter arithmetic and limit enforcement.
type Policy struct {
	Version    string
	Predicates []Predicate
	Budgets    []BudgetDecl
}

// BudgetDecl is a declared budget from a rolling_budget rule: enough for Phase 3.1 to
// know a decision consumes budget (and place a hold). The spend/limit arithmetic is
// Phase 3.2.
type BudgetDecl struct {
	ID       string
	Agents   []string // empty = every agent
	Window   string   // day | month | rolling
	Limit    string
	Currency string
}

// appliesTo reports whether this budget governs the given agent.
func (b BudgetDecl) appliesTo(agentID string) bool {
	if len(b.Agents) == 0 {
		return true
	}
	for _, a := range b.Agents {
		if a == agentID {
			return true
		}
	}
	return false
}

// applicableBudget returns the first budget governing agentID, if any.
func (p Policy) applicableBudget(agentID string) (BudgetDecl, bool) {
	for _, b := range p.Budgets {
		if b.appliesTo(agentID) {
			return b, true
		}
	}
	return BudgetDecl{}, false
}

// BundleProvider resolves the active policy bundle for an org at decision time
// (ROADMAP Task 2.2). It is defined here (not imported from internal/bundle) so the
// engine has no dependency on the control plane — internal/bundle.Provider satisfies it
// structurally. The implementation reads a process-local cache only; the engine never
// makes a synchronous control-plane call on the hot path (TRD §3 boundary rule).
type BundleProvider interface {
	Active(ctx context.Context, orgID string) (Policy, error)
}

// Engine is the deterministic decision engine (TRD §5). Given the same request and
// the same policy + evaluated_at, it always produces the same decision.
//
// Policy resolution: when Provider is set the engine evaluates the org's active bundle
// (per-org, Task 2.2); otherwise it falls back to the static Policy loaded at boot
// (file/GitOps mode, Task 1.7). Either way the decision cites the resolved bundle's
// version hash.
type Engine struct {
	Policy       Policy
	SigningKeyID string
	// Signer applies the Ed25519 decision signature (Task 1.5).
	Signer *signing.Signer
	// Provider, when set, resolves the per-org active bundle (Task 2.2). When nil the
	// engine uses the static Policy for every org.
	Provider BundleProvider
	// HoldTTL is how long a budget hold lives before auto-release (Phase 3.1). The
	// engine stamps it into the capture_within obligation's expires_at; the server
	// places the hold with the same TTL. Zero => DefaultHoldTTL.
	HoldTTL time.Duration
}

// ObligationCaptureWithin is re-exported from the contract for local use (ROADMAP A#2,
// Phase 3.1).
const ObligationCaptureWithin = contractsv1.ObligationCaptureWithin

// DefaultHoldTTL is the fallback hold lifetime when Engine.HoldTTL is unset.
const DefaultHoldTTL = 15 * time.Minute

// NewEngine constructs an Engine over a policy.
func NewEngine(policy Policy, signingKeyID string) Engine {
	return Engine{Policy: policy, SigningKeyID: signingKeyID}
}

// WithSigner returns a copy of the engine that signs decisions with s.
func (e Engine) WithSigner(s *signing.Signer) Engine {
	e.Signer = s
	return e
}

// WithProvider returns a copy of the engine that resolves the per-org active bundle
// via p instead of using the static boot policy (Task 2.2).
func (e Engine) WithProvider(p BundleProvider) Engine {
	e.Provider = p
	return e
}

// WithHoldTTL returns a copy of the engine that stamps budget holds with ttl (Phase 3.1).
func (e Engine) WithHoldTTL(ttl time.Duration) Engine {
	e.HoldTTL = ttl
	return e
}

func (e Engine) holdTTL() time.Duration {
	if e.HoldTTL > 0 {
		return e.HoldTTL
	}
	return DefaultHoldTTL
}

// Authorize implements the server's Authorizer seam: it resolves the org's active
// policy bundle, evaluates the applicable predicates, combines them via the Phase-0
// algebra, and assembles a signed Decision with a structured explanation (TRD §7).
func (e Engine) Authorize(ctx context.Context, orgID string, req contractsv1.AuthorizeRequest, shadow bool) (contractsv1.Decision, error) {
	start := time.Now()

	pol := e.Policy
	if e.Provider != nil {
		resolved, err := e.Provider.Active(ctx, orgID)
		switch {
		case err == nil:
			pol = resolved
		case errors.Is(err, ErrNoActiveBundle) && len(e.Policy.Predicates) > 0:
			// The org has not published a control-plane bundle: fall back to the static
			// boot policy (file/GitOps mode, Task 1.7). Only reached when a static policy
			// is configured; otherwise this is a controlled failure below.
			pol = e.Policy
		default:
			// No servable bundle (or the cache could not produce one): a controlled
			// failure, never a fabricated verdict (§21). The server maps this to 503.
			return contractsv1.Decision{}, err
		}
	}

	evaluatedAt := req.EvaluatedAt
	if evaluatedAt == "" {
		evaluatedAt = start.UTC().Format(time.RFC3339)
	}

	dec := Evaluate(pol, req, evaluatedAt)
	// shadow marks an advisory (log-only) decision the caller must not enforce (A#5).
	// It is part of the SIGNED bytes, so it is set before signing.
	dec.Shadow = shadow

	// Two-phase budget (Phase 3.1, A#2): a NON-shadow APPROVE against a policy that
	// declares a budget for this agent places a hold. The engine declares the hold via
	// a signed capture_within obligation; the server persists the reservation. A shadow
	// decision is advisory and never reserves budget; a DENY/REVIEW consumes nothing.
	if !shadow && dec.Verdict == contractsv1.VerdictApprove {
		if b, ok := pol.applicableBudget(req.AgentID); ok {
			dec.Obligations = append(dec.Obligations, e.captureWithinObligation(b, req, evaluatedAt, dec.DecisionID))
		}
	}

	dec.Signature = contractsv1.Signature{
		Algorithm:        "Ed25519",
		KeyID:            e.SigningKeyID,
		Value:            stubSignatureValue, // placeholder unless a Signer is set
		Canonicalization: signatureCanonicalization,
	}
	if e.Signer != nil {
		if err := e.Signer.Sign(&dec); err != nil {
			return contractsv1.Decision{}, err
		}
	}
	dec.LatencyMs = int(time.Since(start).Milliseconds())
	return dec, nil
}

// captureWithinObligation builds the signed obligation that declares a budget hold on
// an APPROVE. hold_ref is the decision id: capture/void address the hold by it. All
// values are deterministic in (budget, request, evaluated_at), so a replay reproduces
// the identical obligation and signature. expires_at = evaluated_at + TTL.
func (e Engine) captureWithinObligation(b BudgetDecl, req contractsv1.AuthorizeRequest, evaluatedAt, decisionID string) contractsv1.Obligation {
	ttl := e.holdTTL()
	base := time.Now().UTC()
	if t, err := time.Parse(time.RFC3339, evaluatedAt); err == nil {
		base = t.UTC()
	}
	expiresAt := base.Add(ttl).Format(time.RFC3339)
	return contractsv1.Obligation{
		Type:   ObligationCaptureWithin,
		Detail: fmt.Sprintf("Budget %q hold placed for %s %s; capture on payment success or void on failure within %s (else it auto-expires).", b.ID, req.Amount, req.Currency, ttl),
		Params: map[string]interface{}{
			"budget_id":   b.ID,
			"window":      b.Window,
			"amount":      req.Amount,
			"currency":    req.Currency,
			"ttl_seconds": int(ttl.Seconds()),
			"expires_at":  expiresAt,
			"hold_ref":    decisionID,
		},
	}
}

// Evaluate is the pure decision core: it evaluates the applicable predicates against a
// policy and assembles an UNSIGNED Decision (verdict + explanation + cited version).
// It sets no signature, no latency, and no shadow flag — Authorize adds those, and a
// dry-run/simulate (Task 2.3) uses it directly without signing or auditing.
// Deterministic in (pol, req, evaluatedAt): identical inputs → identical output.
func Evaluate(pol Policy, req contractsv1.AuthorizeRequest, evaluatedAt string) contractsv1.Decision {
	in := buildInput(req, evaluatedAt)

	// All six types are local (no I/O), so evaluate them all and let the
	// order-independent algebra combine them (TRD §5).
	results := make([]PredicateResult, 0, len(pol.Predicates))
	matched := make([]contractsv1.MatchedRule, 0, len(pol.Predicates))
	for _, p := range pol.Predicates {
		if !p.AppliesTo(in.AgentID) {
			continue
		}
		r := p.Evaluate(in)
		results = append(results, PredicateResult{
			RuleID:   p.RuleID(),
			Enriched: false,
			Outcome:  r.Outcome,
		})
		matched = append(matched, contractsv1.MatchedRule{
			RuleID:   p.RuleID(),
			Type:     p.Type(),
			Result:   toContractResult(r.Outcome),
			Detail:   r.Reason,
			Evidence: r.Evidence,
		})
	}

	verdict := Combine(results)
	return contractsv1.Decision{
		DecisionID:        ulid.New(),
		Verdict:           toContractVerdict(verdict),
		PolicyVersionHash: pol.Version,
		Explanation:       assembleExplanation(verdict, matched),
		Obligations:       []contractsv1.Obligation{},
		EvaluatedAt:       evaluatedAt,
	}
}

// buildInput normalizes the request into the deterministic evaluation vector.
func buildInput(req contractsv1.AuthorizeRequest, evaluatedAt string) Input {
	amount, _ := parseMoney(req.Amount) // nil if unparseable; predicates handle nil

	// evaluatedAt is RFC 3339 (validated/stamped upstream); on a parse miss we fall
	// back to zero time, which time-window predicates treat deterministically.
	t, err := time.Parse(time.RFC3339, evaluatedAt)
	if err != nil {
		t = time.Time{}
	}

	return Input{
		AgentID:      req.AgentID,
		Action:       req.Action,
		AmountRaw:    req.Amount,
		Amount:       amount,
		Currency:     req.Currency,
		Target:       req.Target,
		Jurisdiction: req.Jurisdiction,
		EvaluatedAt:  t,
		Context:      req.Context,
	}
}

// assembleExplanation builds the structured explanation (TRD §7): a plain-English
// summary naming the deciding rule, plus every matched rule with its evidence.
func assembleExplanation(v Verdict, matched []contractsv1.MatchedRule) contractsv1.Explanation {
	return contractsv1.Explanation{
		Summary:      summarize(v, matched),
		MatchedRules: matched,
	}
}

// summarize produces the one-line human summary. For DENY/REVIEW it names the first
// rule that drove the verdict; for APPROVE it states how many rules were satisfied.
func summarize(v Verdict, matched []contractsv1.MatchedRule) string {
	switch v {
	case Deny:
		if len(matched) == 0 {
			return "No applicable policy rule granted authority; denied by default."
		}
		if r, ok := firstWithResult(matched, contractsv1.ResultDenied); ok {
			return fmt.Sprintf("Denied by rule %q: %s", r.RuleID, r.Detail)
		}
		// Deny without an explicit DENIED rule means a fail-closed-to-deny; name it.
		if r, ok := firstWithResult(matched, contractsv1.ResultUnavailable); ok {
			return fmt.Sprintf("Denied: rule %q could not complete and is fail-closed.", r.RuleID)
		}
		return "Denied."
	case Review:
		if r, ok := firstWithResult(matched, contractsv1.ResultReview); ok {
			return fmt.Sprintf("Flagged for review by rule %q: %s", r.RuleID, r.Detail)
		}
		if r, ok := firstWithResult(matched, contractsv1.ResultUnavailable); ok {
			return fmt.Sprintf("Flagged for review: rule %q could not complete.", r.RuleID)
		}
		return "Flagged for review."
	default: // Approve
		return fmt.Sprintf("Approved: all %d applicable rule(s) satisfied.", len(matched))
	}
}

func firstWithResult(matched []contractsv1.MatchedRule, want contractsv1.PredicateResult) (contractsv1.MatchedRule, bool) {
	for _, m := range matched {
		if m.Result == want {
			return m, true
		}
	}
	return contractsv1.MatchedRule{}, false
}

// toContractResult maps an internal Outcome to the contract's PredicateResult.
func toContractResult(o Outcome) contractsv1.PredicateResult {
	switch o {
	case Satisfied:
		return contractsv1.ResultSatisfied
	case Denied:
		return contractsv1.ResultDenied
	case Flagged:
		return contractsv1.ResultReview
	case Unavailable:
		return contractsv1.ResultUnavailable
	default:
		return contractsv1.ResultReview
	}
}

// toContractVerdict maps an internal Verdict to the contract's Verdict.
func toContractVerdict(v Verdict) contractsv1.Verdict {
	switch v {
	case Approve:
		return contractsv1.VerdictApprove
	case Deny:
		return contractsv1.VerdictDeny
	default:
		return contractsv1.VerdictReview
	}
}

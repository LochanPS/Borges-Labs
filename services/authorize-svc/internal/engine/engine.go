package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	"github.com/trust-infra/authorize-svc/internal/ulid"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Policy is an in-memory, immutable set of predicates the engine evaluates. In MVP it
// is constructed from a fixture; Phase 2 loads it from a published, content-hashed
// bundle. Version is the policy_version_hash every decision cites.
type Policy struct {
	Version    string
	Predicates []Predicate
}

// Engine is the deterministic decision engine (TRD §5). Given the same request and
// the same policy + evaluated_at, it always produces the same decision.
//
// Signature note: this phase still attaches the PLACEHOLDER signature (see
// authorize.go). Real Ed25519 signing lands in Task 1.5 and replaces only the
// signing step; the decision assembly here does not change.
type Engine struct {
	Policy       Policy
	SigningKeyID string
	// Signer, when set, applies a real Ed25519 signature (Task 1.5); when nil the
	// decision carries the placeholder signature.
	Signer *signing.Signer
}

// NewEngine constructs an Engine over a policy.
func NewEngine(policy Policy, signingKeyID string) Engine {
	return Engine{Policy: policy, SigningKeyID: signingKeyID}
}

// WithSigner returns a copy of the engine that signs decisions with s.
func (e Engine) WithSigner(s *signing.Signer) Engine {
	e.Signer = s
	return e
}

// Authorize implements the server's Authorizer seam: it evaluates the applicable
// predicates, combines them via the Phase-0 algebra, and assembles a signed Decision
// with a structured explanation (TRD §7).
func (e Engine) Authorize(_ context.Context, req contractsv1.AuthorizeRequest) (contractsv1.Decision, error) {
	start := time.Now()

	evaluatedAt := req.EvaluatedAt
	if evaluatedAt == "" {
		evaluatedAt = start.UTC().Format(time.RFC3339)
	}
	in := buildInput(req, evaluatedAt)

	// Evaluate every applicable predicate. All six types are local (no I/O), so we
	// evaluate them all and let the order-independent algebra combine them; the
	// "short-circuit on hard DENY" in TRD §5 is what lets us skip ENRICHED
	// predicates once a local deny exists — there are none in this phase.
	results := make([]PredicateResult, 0, len(e.Policy.Predicates))
	matched := make([]contractsv1.MatchedRule, 0, len(e.Policy.Predicates))
	for _, p := range e.Policy.Predicates {
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
	explanation := assembleExplanation(verdict, matched)

	dec := contractsv1.Decision{
		DecisionID:        ulid.New(),
		Verdict:           toContractVerdict(verdict),
		PolicyVersionHash: e.Policy.Version,
		Explanation:       explanation,
		Obligations:       []contractsv1.Obligation{},
		EvaluatedAt:       evaluatedAt,
		Signature: contractsv1.Signature{
			Algorithm:        "Ed25519",
			KeyID:            e.SigningKeyID,
			Value:            stubSignatureValue, // placeholder unless a Signer is set
			Canonicalization: signatureCanonicalization,
		},
	}
	if e.Signer != nil {
		if err := e.Signer.Sign(&dec); err != nil {
			return contractsv1.Decision{}, err
		}
	}
	dec.LatencyMs = int(time.Since(start).Milliseconds())
	return dec, nil
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

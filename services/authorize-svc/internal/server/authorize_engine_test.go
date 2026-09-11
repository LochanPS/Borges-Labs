package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/policy"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// e2ePolicy scopes one predicate to one agent, so a request from a given agent is
// decided by exactly that predicate — letting each DENY path be triggered in
// isolation through the real HTTP surface. time_window is deliberately full-day
// (satisfied) here because evaluated_at is service-stamped (not client-controllable)
// end to end; its DENY path is covered in engine/predicates_test.go.
const e2ePolicy = `{
  "version": "pol_e2e_v1",
  "predicates": [
    {"id":"lim",   "type":"per_transaction_limit", "agents":["lim-agent"],   "max":"100.00", "currency":"USD"},
    {"id":"allow", "type":"vendor_allowlist",       "agents":["allow-agent"], "vendors":["good-vendor"]},
    {"id":"block", "type":"vendor_blocklist",       "agents":["block-agent"], "vendors":["bad-vendor"]},
    {"id":"perm",  "type":"agent_permission",       "agents":["perm-agent"],  "allowed_actions":["payment.create"]},
    {"id":"juris", "type":"jurisdiction_currency",  "agents":["juris-agent"], "allowed":{"US":["USD"]}},
    {"id":"review","type":"per_transaction_limit",  "agents":["review-agent"],"max":"100.00", "currency":"EUR"},
    {"id":"ok",    "type":"per_transaction_limit",  "agents":["ok-agent"],    "max":"100000.00", "currency":"USD"}
  ]
}`

// newEngineHarness builds a harness whose authorizer is the REAL deterministic
// engine over the given policy JSON (Task 1.7 — replaces the hardcoded APPROVE).
func newEngineHarness(t *testing.T, policyJSON string) *authHarness {
	t.Helper()
	pol, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatalf("parse e2e policy: %v", err)
	}
	generous := ratelimit.TierTable{"default": {PerMinute: 1_000_000, PerSecond: 1_000_000}}
	return newAuthHarnessFull(t, testLimiter(), generous, func(s *signing.Signer) Authorizer {
		return engine.NewEngine(pol, s.KeyID()).WithSigner(s)
	})
}

// decodeDecision unmarshals a Decision from a response body.
func decodeDecision(t *testing.T, body []byte) contractsv1.Decision {
	t.Helper()
	var dec contractsv1.Decision
	if err := json.Unmarshal(body, &dec); err != nil {
		t.Fatalf("decode decision: %v; body: %s", err, body)
	}
	return dec
}

// reqBody builds an authorize body for a given agent/action/amount/currency/vendor.
func reqBody(agent, action, amount, currency, vendor, jurisdiction, idemKey string) []byte {
	return []byte(fmt.Sprintf(`{
	  "agent_id": %q, "action": %q, "amount": %q, "currency": %q,
	  "target": { "type": "vendor", "id": %q }, "jurisdiction": %q,
	  "idempotency_key": %q
	}`, agent, action, amount, currency, vendor, jurisdiction, idemKey))
}

// ACCEPTANCE (Task 1.7): the real engine produces a genuine APPROVE end to end
// (not the old hardcoded APPROVE), signed and schema-valid.
func TestEngineE2E_Approve(t *testing.T) {
	h := newEngineHarness(t, e2ePolicy)
	decisionSchema := compileContract(t, decisionSchemaID)

	body := reqBody("ok-agent", "payment.create", "5000.00", "USD", "acme", "US", "idem_ok_approve_0001")
	resp, respBody := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", body, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; body: %s", resp.StatusCode, respBody)
	}
	validateAgainst(t, decisionSchema, respBody)

	dec := decodeDecision(t, respBody)
	if dec.Verdict != contractsv1.VerdictApprove {
		t.Fatalf("verdict = %q, want APPROVE", dec.Verdict)
	}
	if dec.PolicyVersionHash != "pol_e2e_v1" {
		t.Errorf("policy_version_hash = %q, want pol_e2e_v1", dec.PolicyVersionHash)
	}
	if len(dec.Explanation.MatchedRules) == 0 {
		t.Error("expected matched_rules in the explanation")
	}
}

// ACCEPTANCE (Task 1.7): a DENY for each local predicate, through the HTTP surface.
func TestEngineE2E_DenyPerPredicate(t *testing.T) {
	h := newEngineHarness(t, e2ePolicy)

	cases := []struct {
		name string
		body []byte
	}{
		{"per_transaction_limit", reqBody("lim-agent", "payment.create", "500.00", "USD", "acme", "US", "idem_deny_lim_00001")},
		{"vendor_allowlist", reqBody("allow-agent", "payment.create", "10.00", "USD", "not-listed", "US", "idem_deny_allow_001")},
		{"vendor_blocklist", reqBody("block-agent", "payment.create", "10.00", "USD", "bad-vendor", "US", "idem_deny_block_001")},
		{"agent_permission", reqBody("perm-agent", "wire.send", "10.00", "USD", "acme", "US", "idem_deny_perm_0001")},
		{"jurisdiction_currency", reqBody("juris-agent", "payment.create", "10.00", "EUR", "acme", "US", "idem_deny_juris_001")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", c.body, h.active))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d; body: %s", resp.StatusCode, body)
			}
			dec := decodeDecision(t, body)
			if dec.Verdict != contractsv1.VerdictDeny {
				t.Fatalf("verdict = %q, want DENY (body: %s)", dec.Verdict, body)
			}
		})
	}
}

// ACCEPTANCE (Task 1.7): a REVIEW verdict (a flagged predicate — here a currency
// mismatch the engine cannot compare, which routes to human review, not a deny).
func TestEngineE2E_Review(t *testing.T) {
	h := newEngineHarness(t, e2ePolicy)
	body := reqBody("review-agent", "payment.create", "10.00", "USD", "acme", "US", "idem_review_00001")
	resp, respBody := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", body, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; body: %s", resp.StatusCode, respBody)
	}
	if v := decodeDecision(t, respBody).Verdict; v != contractsv1.VerdictReview {
		t.Fatalf("verdict = %q, want REVIEW", v)
	}
}

// ACCEPTANCE (Task 1.7): the same idempotency key returns the SAME decision (same
// decision_id + verdict), flagged as a replay — no second, divergent decision.
func TestEngineE2E_IdempotentReplay(t *testing.T) {
	h := newEngineHarness(t, e2ePolicy)
	body := reqBody("ok-agent", "payment.create", "5000.00", "USD", "acme", "US", "idem_replay_key_0001")

	resp1, body1 := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", body, h.active))
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d; body: %s", resp1.StatusCode, body1)
	}
	if got := resp1.Header.Get("X-Idempotent-Replay"); got != "" {
		t.Errorf("first response marked as replay (%q); want fresh", got)
	}
	first := decodeDecision(t, body1)

	resp2, body2 := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", body, h.active))
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("replay status = %d; body: %s", resp2.StatusCode, body2)
	}
	if got := resp2.Header.Get("X-Idempotent-Replay"); got != "true" {
		t.Errorf("X-Idempotent-Replay = %q, want true", got)
	}
	second := decodeDecision(t, body2)

	if first.DecisionID != second.DecisionID {
		t.Errorf("decision_id changed on replay: %s -> %s (idempotency broken)", first.DecisionID, second.DecisionID)
	}
	if first.Verdict != second.Verdict {
		t.Errorf("verdict changed on replay: %s -> %s", first.Verdict, second.Verdict)
	}
}

// A different idempotency key yields a distinct decision (no false-sharing).
func TestEngineE2E_DistinctKeysDistinctDecisions(t *testing.T) {
	h := newEngineHarness(t, e2ePolicy)
	b1 := reqBody("ok-agent", "payment.create", "5000.00", "USD", "acme", "US", "idem_distinct_a_0001")
	b2 := reqBody("ok-agent", "payment.create", "5000.00", "USD", "acme", "US", "idem_distinct_b_0001")

	_, r1 := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", b1, h.active))
	_, r2 := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", b2, h.active))
	if decodeDecision(t, r1).DecisionID == decodeDecision(t, r2).DecisionID {
		t.Error("distinct idempotency keys produced the same decision_id")
	}
}

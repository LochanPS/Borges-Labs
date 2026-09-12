package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// fixturePolicy is a representative six-predicate policy exercised end-to-end.
func fixturePolicy() Policy {
	return Policy{
		Version: "pol_test_0000000000000000000000000000000000000000000000000000000000000000",
		Predicates: []Predicate{
			PerTransactionLimit{base: base{ID: "per_txn_limit"}, MaxRaw: "5000.00", Currency: "USD"},
			VendorAllowlist{base: base{ID: "vendor_allow"}, Vendors: []string{"acme", "globex"}},
			VendorBlocklist{base: base{ID: "vendor_block"}, Vendors: []string{"evilcorp"}},
			AgentPermission{base: base{ID: "agent_perm"}, AllowedActions: []string{"payment.create"}},
			TimeWindow{base: base{ID: "biz_hours"}, StartMinute: 9 * 60, EndMinute: 17 * 60, Weekdays: []int{1, 2, 3, 4, 5}},
			JurisdictionCurrency{base: base{ID: "juris_ccy"}, Allowed: map[string][]string{"US": {"USD"}}},
		},
	}
}

const monNoon = "2026-08-31T12:00:00Z" // a Monday, inside business hours

func baseReq() contractsv1.AuthorizeRequest {
	return contractsv1.AuthorizeRequest{
		AgentID:        "agent-1",
		Action:         "payment.create",
		Amount:         "1000.00",
		Currency:       "USD",
		Target:         contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
		Jurisdiction:   "US",
		IdempotencyKey: "idem_engine_test_1",
		EvaluatedAt:    monNoon,
	}
}

func authorize(t *testing.T, req contractsv1.AuthorizeRequest) contractsv1.Decision {
	t.Helper()
	e := NewEngine(fixturePolicy(), "azn-sign-test")
	dec, err := e.Authorize(context.Background(), "", req, false)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return dec
}

func TestEngine_Approve(t *testing.T) {
	dec := authorize(t, baseReq())
	if dec.Verdict != contractsv1.VerdictApprove {
		t.Fatalf("verdict = %q, want APPROVE; summary: %s", dec.Verdict, dec.Explanation.Summary)
	}
	// Explanation shape (TRD §7): summary + one matched rule per applicable predicate.
	if dec.Explanation.Summary == "" {
		t.Error("empty summary")
	}
	if len(dec.Explanation.MatchedRules) != 6 {
		t.Fatalf("matched rules = %d, want 6", len(dec.Explanation.MatchedRules))
	}
	for _, m := range dec.Explanation.MatchedRules {
		if m.RuleID == "" || m.Type == "" || m.Result == "" || m.Detail == "" {
			t.Errorf("incomplete matched rule: %+v", m)
		}
		if m.Result != contractsv1.ResultSatisfied {
			t.Errorf("rule %s = %s, want SATISFIED", m.RuleID, m.Result)
		}
	}
	if dec.PolicyVersionHash != fixturePolicy().Version {
		t.Error("policy version hash not cited")
	}
	if dec.EvaluatedAt != monNoon {
		t.Errorf("evaluated_at = %q, want injected %q", dec.EvaluatedAt, monNoon)
	}
}

func TestEngine_DenyOnLimit(t *testing.T) {
	req := baseReq()
	req.Amount = "6000.00" // over the 5000 limit
	dec := authorize(t, req)

	if dec.Verdict != contractsv1.VerdictDeny {
		t.Fatalf("verdict = %q, want DENY", dec.Verdict)
	}
	if !strings.Contains(dec.Explanation.Summary, "per_txn_limit") {
		t.Errorf("summary should name the denying rule; got %q", dec.Explanation.Summary)
	}
	r, ok := firstWithResult(dec.Explanation.MatchedRules, contractsv1.ResultDenied)
	if !ok || r.RuleID != "per_txn_limit" {
		t.Errorf("expected per_txn_limit DENIED, got %+v (ok=%v)", r, ok)
	}
}

func TestEngine_DenyOnBlocklist(t *testing.T) {
	req := baseReq()
	req.Target = contractsv1.Target{Type: contractsv1.TargetVendor, ID: "evilcorp"}
	dec := authorize(t, req)
	// evilcorp is blocklisted AND not allowlisted — both deny; verdict is DENY.
	if dec.Verdict != contractsv1.VerdictDeny {
		t.Fatalf("verdict = %q, want DENY", dec.Verdict)
	}
}

func TestEngine_ReviewOnCurrencyMismatch(t *testing.T) {
	req := baseReq()
	req.Currency = "EUR"
	req.Jurisdiction = "" // unconstrained, so only the limit's currency mismatch flags
	dec := authorize(t, req)

	if dec.Verdict != contractsv1.VerdictReview {
		t.Fatalf("verdict = %q, want REVIEW; summary: %s", dec.Verdict, dec.Explanation.Summary)
	}
	r, ok := firstWithResult(dec.Explanation.MatchedRules, contractsv1.ResultReview)
	if !ok || r.RuleID != "per_txn_limit" {
		t.Errorf("expected per_txn_limit REVIEW, got %+v (ok=%v)", r, ok)
	}
}

func TestEngine_EmptyPolicyDeniesByDefault(t *testing.T) {
	e := NewEngine(Policy{Version: "pol_empty"}, "k")
	dec, err := e.Authorize(context.Background(), "", baseReq(), false)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if dec.Verdict != contractsv1.VerdictDeny {
		t.Fatalf("verdict = %q, want DENY (deny-by-default)", dec.Verdict)
	}
	if len(dec.Explanation.MatchedRules) != 0 {
		t.Errorf("expected no matched rules, got %d", len(dec.Explanation.MatchedRules))
	}
	if !strings.Contains(strings.ToLower(dec.Explanation.Summary), "default") {
		t.Errorf("summary should explain deny-by-default; got %q", dec.Explanation.Summary)
	}
}

func TestEngine_AgentScopingFiltersRules(t *testing.T) {
	// A rule scoped to a different agent must not apply.
	pol := Policy{Version: "pol_scoped", Predicates: []Predicate{
		PerTransactionLimit{base: base{ID: "other_agent_limit", Agents: []string{"agent-2"}}, MaxRaw: "1.00", Currency: "USD"},
		VendorAllowlist{base: base{ID: "allow_all_agents"}, Vendors: []string{"acme"}},
	}}
	e := NewEngine(pol, "k")
	dec, _ := e.Authorize(context.Background(), "", baseReq(), false) // agent-1, amount 1000
	// The 1.00 limit is scoped to agent-2, so it must NOT deny agent-1.
	if dec.Verdict != contractsv1.VerdictApprove {
		t.Fatalf("verdict = %q, want APPROVE (scoped rule should not apply)", dec.Verdict)
	}
	if len(dec.Explanation.MatchedRules) != 1 {
		t.Errorf("matched rules = %d, want 1 (only the unscoped rule)", len(dec.Explanation.MatchedRules))
	}
}

func TestEngine_Deterministic(t *testing.T) {
	req := baseReq()
	d1 := authorize(t, req)
	d2 := authorize(t, req)

	if d1.Verdict != d2.Verdict {
		t.Fatalf("verdict differs across identical inputs: %q vs %q", d1.Verdict, d2.Verdict)
	}
	// Matched rules (the policy-driven part) must be byte-identical; only the
	// decision_id and latency are allowed to differ.
	j1, _ := json.Marshal(d1.Explanation)
	j2, _ := json.Marshal(d2.Explanation)
	if string(j1) != string(j2) {
		t.Errorf("explanation not deterministic:\n%s\n%s", j1, j2)
	}
	if d1.DecisionID == d2.DecisionID {
		t.Error("decision ids should be unique per call")
	}
}

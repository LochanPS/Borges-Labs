package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/hold"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// budgetRules is a policy that declares a monthly budget for the agent, so an APPROVE
// is budget-affecting and places a hold.
func budgetRules() []map[string]any {
	return []map[string]any{
		{"id": "limit", "type": "per_transaction_limit", "max": "5000.00", "currency": "USD"},
		{"id": "perm", "type": "agent_permission", "allowed_actions": []string{"payment.create"}},
		{"id": "monthly", "type": "rolling_budget", "window": "month", "limit": "50000.00", "currency": "USD"},
	}
}

// publishBudgetPolicy creates + publishes a budget policy and returns nothing (the org
// bundle is now active). Uses the advisory key for authoring (any valid key works).
func (h *cpHarness) publishBudgetPolicy(t *testing.T) {
	t.Helper()
	createBody := mustJSON(t, map[string]any{"name": "budgeted", "rules": budgetRules()})
	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, body)
	}
	var pol struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &pol)
	resp, body = do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/publish", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish status = %d; body: %s", resp.StatusCode, body)
	}
}

// authorizeEnforce runs a binding (enforce-key) authorize and returns the decision.
func (h *cpHarness) authorizeEnforce(t *testing.T, amount, idem string) contractsv1.Decision {
	t.Helper()
	body := mustJSON(t, contractsv1.AuthorizeRequest{
		AgentID: "agent-a", Action: "payment.create", Amount: amount, Currency: "USD",
		Target:         contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
		IdempotencyKey: idem,
	})
	resp, respBody := do(t, h.sign(t, http.MethodPost, "/v1/authorize", body, h.enforce))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, respBody)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(respBody, &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	return dec
}

// ACCEPTANCE: authorize (budget-affecting) → the decision carries a capture_within
// obligation → capture commits; voiding a captured hold is rejected.
func TestHold_AuthorizeThenCapture(t *testing.T) {
	h := newCPHarness(t)
	h.publishBudgetPolicy(t)

	dec := h.authorizeEnforce(t, "100.00", "idem_hold_cap_1")
	if _, ok := findObligation(dec.Obligations, contractsv1.ObligationCaptureWithin); !ok {
		t.Fatal("budget-affecting APPROVE has no capture_within obligation")
	}
	if dec.Shadow {
		t.Fatal("enforce-key decision must not be shadow")
	}

	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/capture", nil, h.enforce))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("capture status = %d; body: %s", resp.StatusCode, body)
	}
	var hr holdResponse
	_ = json.Unmarshal(body, &hr)
	if hr.State != hold.StateCaptured {
		t.Errorf("state = %s, want captured", hr.State)
	}

	// Capture is idempotent.
	resp, _ = do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/capture", nil, h.enforce))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("second capture status = %d, want 200 (idempotent)", resp.StatusCode)
	}

	// Voiding a captured hold is a 409.
	resp, _ = do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/void", nil, h.enforce))
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("void-after-capture status = %d, want 409", resp.StatusCode)
	}
}

// ACCEPTANCE: authorize → void releases; capturing a voided hold is rejected.
func TestHold_AuthorizeThenVoid(t *testing.T) {
	h := newCPHarness(t)
	h.publishBudgetPolicy(t)
	dec := h.authorizeEnforce(t, "200.00", "idem_hold_void_1")

	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/void", nil, h.enforce))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("void status = %d; body: %s", resp.StatusCode, body)
	}
	var hr holdResponse
	_ = json.Unmarshal(body, &hr)
	if hr.State != hold.StateVoided {
		t.Errorf("state = %s, want voided", hr.State)
	}

	resp, _ = do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/capture", nil, h.enforce))
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("capture-after-void status = %d, want 409", resp.StatusCode)
	}
}

// ACCEPTANCE: a retried authorize with the same idempotency key returns the same
// decision (one hold, not two).
func TestHold_IdempotentAuthorizeNoDoubleHold(t *testing.T) {
	h := newCPHarness(t)
	h.publishBudgetPolicy(t)

	d1 := h.authorizeEnforce(t, "100.00", "idem_hold_dupe_1")
	d2 := h.authorizeEnforce(t, "100.00", "idem_hold_dupe_1")
	if d1.DecisionID != d2.DecisionID {
		t.Fatalf("idempotent authorize returned different decisions: %s vs %s", d1.DecisionID, d2.DecisionID)
	}
	// The single hold captures once.
	resp, _ := do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+d1.DecisionID+"/capture", nil, h.enforce))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("capture status = %d, want 200", resp.StatusCode)
	}
}

// A non-budget APPROVE places no hold; capture is a 404.
func TestHold_NonBudgetHasNoHold(t *testing.T) {
	h := newCPHarness(t)
	// validRules() has no rolling_budget.
	createBody := mustJSON(t, map[string]any{"name": "nobudget", "rules": validRules()})
	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, body)
	}
	var pol struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &pol)
	do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/publish", nil, h.active))

	dec := h.authorizeEnforce(t, "100.00", "idem_nobudget_1")
	if _, ok := findObligation(dec.Obligations, contractsv1.ObligationCaptureWithin); ok {
		t.Fatal("non-budget APPROVE attached a capture_within obligation")
	}
	resp, _ = do(t, h.sign(t, http.MethodPost, "/v1/authorize/"+dec.DecisionID+"/capture", nil, h.enforce))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("capture of a no-hold decision status = %d, want 404", resp.StatusCode)
	}
}

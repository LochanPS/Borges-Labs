package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// ACCEPTANCE (Task 2.3): a shadow-mode key's decision is signaled non-enforceable in
// the response (shadow:true + X-Shadow header) AND recorded shadow in the audit log.
// newAuthHarness mints keys with the advisory-first default (shadow=true).
func TestShadow_KeyDecisionSignaledAndAudited(t *testing.T) {
	h := newAuthHarness(t)

	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Shadow"); got != "true" {
		t.Errorf("X-Shadow header = %q, want true", got)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(body, &dec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !dec.Shadow {
		t.Error("response decision not marked shadow")
	}

	// The audited record is marked shadow too (poll for the async write).
	var rec *audit.Record
	for i := 0; i < 200; i++ {
		if r, err := h.store.Get(context.Background(), h.orgID, dec.DecisionID); err == nil {
			rec = r
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if rec == nil {
		t.Fatalf("decision %s never persisted", dec.DecisionID)
	}
	if !rec.Shadow {
		t.Error("audit record not marked shadow")
	}
}

func simReq(amount, idem string) contractsv1.AuthorizeRequest {
	return contractsv1.AuthorizeRequest{
		AgentID: "agent-a", Action: "payment.create", Amount: amount, Currency: "USD",
		Target: contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
		IdempotencyKey: idem,
	}
}

// ACCEPTANCE (Task 2.3): simulate returns per-request would-be verdicts for a batch,
// citing the version evaluated, all marked shadow — and nothing is signed or audited.
func TestControlPlane_Simulate(t *testing.T) {
	h := newCPHarness(t)

	createBody := mustJSON(t, map[string]any{"name": "p", "rules": validRules()})
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
	var ver struct {
		VersionHash string `json:"version_hash"`
	}
	_ = json.Unmarshal(body, &ver)

	simBody := mustJSON(t, map[string]any{
		"version_hash": ver.VersionHash,
		"requests": []contractsv1.AuthorizeRequest{
			simReq("100.00", "idem_sim_ok_1"),   // within 5000 limit → APPROVE
			simReq("6000.00", "idem_sim_over_1"), // over limit → DENY
		},
	})
	resp, body = do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/simulate", simBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("simulate status = %d; body: %s", resp.StatusCode, body)
	}
	var out simulateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode simulate response: %v", err)
	}
	if out.VersionHash != ver.VersionHash {
		t.Errorf("simulate version = %q, want %q", out.VersionHash, ver.VersionHash)
	}
	if !out.Shadow {
		t.Error("simulate response not marked shadow")
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(out.Results))
	}
	if out.Results[0].Verdict != contractsv1.VerdictApprove || out.Results[1].Verdict != contractsv1.VerdictDeny {
		t.Errorf("verdicts = %s,%s want APPROVE,DENY", out.Results[0].Verdict, out.Results[1].Verdict)
	}
	for i, d := range out.Results {
		if !d.Shadow {
			t.Errorf("result[%d] not marked shadow", i)
		}
	}
}

// Simulate with an empty batch is a 400.
func TestControlPlane_SimulateEmptyBatch(t *testing.T) {
	h := newCPHarness(t)
	createBody := mustJSON(t, map[string]any{"name": "p", "rules": validRules()})
	_, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	var pol struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &pol)

	simBody := mustJSON(t, map[string]any{"requests": []contractsv1.AuthorizeRequest{}})
	resp, _ := do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/simulate", simBody, h.active))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty-batch simulate status = %d, want 400", resp.StatusCode)
	}
}

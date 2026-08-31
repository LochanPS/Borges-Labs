package contractsv1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const examplesDir = "../../../examples"

func readExample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatalf("read example %s: %v", name, err)
	}
	return b
}

func TestAuthorizeRequestRoundTrip(t *testing.T) {
	raw := readExample(t, "authorize-request.example.json")
	var req AuthorizeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal AuthorizeRequest: %v", err)
	}
	if req.AgentID != "procurement-agent-v2" {
		t.Errorf("agent_id = %q", req.AgentID)
	}
	if req.Amount != "5000.00" {
		t.Errorf("amount = %q, want string decimal", req.Amount)
	}
	if req.Target.Type != TargetVendor || req.Target.ID != "acme-supplies" {
		t.Errorf("target = %+v", req.Target)
	}
	if req.EvaluatedAt == "" {
		t.Error("evaluated_at must be present (orchestrator-injected input)")
	}
	if req.CounterSnapshot == nil || len(req.CounterSnapshot.Counters) != 1 {
		t.Fatalf("counter_snapshot missing/short: %+v", req.CounterSnapshot)
	}
	if got := req.CounterSnapshot.Counters[0].SpendToDate; got != "48200.00" {
		t.Errorf("spend_to_date = %q", got)
	}
	// Re-marshal and re-unmarshal must be stable.
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var again AuthorizeRequest
	if err := json.Unmarshal(out, &again); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
}

func TestDecisionApprove(t *testing.T) {
	var dec Decision
	if err := json.Unmarshal(readExample(t, "decision-approve.example.json"), &dec); err != nil {
		t.Fatalf("unmarshal APPROVE: %v", err)
	}
	if dec.Verdict != VerdictApprove {
		t.Errorf("verdict = %q, want APPROVE", dec.Verdict)
	}
	if dec.Signature.Algorithm != "Ed25519" {
		t.Errorf("decision signature must be Ed25519, got %q", dec.Signature.Algorithm)
	}
	if dec.Signature.KeyID == "" {
		t.Error("signature.key_id required for rotation")
	}
	if len(dec.Explanation.MatchedRules) == 0 {
		t.Error("APPROVE must list satisfied rules")
	}
	for _, r := range dec.Explanation.MatchedRules {
		if r.Result != ResultSatisfied {
			t.Errorf("APPROVE rule %s result = %q, want SATISFIED", r.RuleID, r.Result)
		}
	}
}

func TestDecisionDeny(t *testing.T) {
	var dec Decision
	if err := json.Unmarshal(readExample(t, "decision-deny.example.json"), &dec); err != nil {
		t.Fatalf("unmarshal DENY: %v", err)
	}
	if dec.Verdict != VerdictDeny {
		t.Errorf("verdict = %q, want DENY", dec.Verdict)
	}
	var denied bool
	for _, r := range dec.Explanation.MatchedRules {
		if r.Result == ResultDenied {
			denied = true
		}
	}
	if !denied {
		t.Error("DENY must contain at least one DENIED rule")
	}
	if dec.Obligations == nil {
		t.Error("obligations must be present (empty array allowed)")
	}
}

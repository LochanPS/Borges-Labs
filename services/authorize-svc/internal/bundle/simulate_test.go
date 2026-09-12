package bundle

import (
	"context"
	"errors"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/policyctl"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Simulate against a published version returns per-request would-be verdicts, all
// marked shadow, citing the version evaluated.
func TestSimulate_AgainstPublishedVersion(t *testing.T) {
	h := newHarness(t)
	v := h.publish(t, "org1", "5000.00") // limit 5000
	id := policyIDOf(t, h, "org1")
	sim := NewSimulator(h.store)

	label, results, err := sim.Simulate(context.Background(), "org1", id, v, []contractsv1.AuthorizeRequest{
		req("100.00"),  // within limit → APPROVE
		req("6000.00"), // over limit → DENY
	})
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if label != v {
		t.Errorf("label = %q, want version %q", label, v)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].Verdict != contractsv1.VerdictApprove || results[1].Verdict != contractsv1.VerdictDeny {
		t.Errorf("verdicts = %s,%s want APPROVE,DENY", results[0].Verdict, results[1].Verdict)
	}
	for i, d := range results {
		if !d.Shadow {
			t.Errorf("result[%d] not marked shadow (a simulation must never be enforceable)", i)
		}
		if d.Signature.Value != "" {
			t.Errorf("result[%d] is signed; simulation results must be unsigned", i)
		}
	}
}

// Simulate against the working-copy draft (no version_hash) previews unpublished edits.
func TestSimulate_AgainstDraft(t *testing.T) {
	h := newHarness(t)
	_ = h.publish(t, "org1", "5000.00")
	id := policyIDOf(t, h, "org1")

	// Tighten the draft to a 50 limit WITHOUT publishing.
	if _, err := h.svc.Update(context.Background(), "org1", id, "", nil, rules("50.00")); err != nil {
		t.Fatalf("update draft: %v", err)
	}
	sim := NewSimulator(h.store)
	label, results, err := sim.Simulate(context.Background(), "org1", id, "", []contractsv1.AuthorizeRequest{req("100.00")})
	if err != nil {
		t.Fatalf("simulate draft: %v", err)
	}
	if label != "draft:"+id {
		t.Errorf("label = %q, want draft:%s", label, id)
	}
	if results[0].Verdict != contractsv1.VerdictDeny {
		t.Errorf("draft verdict = %s, want DENY (100 > tightened 50 limit)", results[0].Verdict)
	}
	// The published version is unchanged: simulating it still APPROVES 100.
	pubHash, _ := h.store.GetActiveBundle(context.Background(), "org1")
	_, pubResults, _ := sim.Simulate(context.Background(), "org1", id, pubHash.VersionHash, []contractsv1.AuthorizeRequest{req("100.00")})
	if pubResults[0].Verdict != contractsv1.VerdictApprove {
		t.Errorf("published verdict = %s, want APPROVE (draft edit must not affect it)", pubResults[0].Verdict)
	}
}

// Simulating an invalid draft is rejected with a ValidationError (same gate as publish).
func TestSimulate_InvalidDraftRejected(t *testing.T) {
	h := newHarness(t)
	p, err := h.svc.Create(context.Background(), "org1", "p", nil, []policyctl.Rule{
		{ID: "bad", Type: "per_transaction_limit"}, // missing max
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	sim := NewSimulator(h.store)
	_, _, err = sim.Simulate(context.Background(), "org1", p.ID, "", []contractsv1.AuthorizeRequest{req("100.00")})
	var ve *policyctl.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (%T), want *policyctl.ValidationError", err, err)
	}
}

// Simulating an unknown version is a not-found error.
func TestSimulate_UnknownVersion(t *testing.T) {
	h := newHarness(t)
	_ = h.publish(t, "org1", "5000.00")
	id := policyIDOf(t, h, "org1")
	sim := NewSimulator(h.store)
	if _, _, err := sim.Simulate(context.Background(), "org1", id, "polv_nope", []contractsv1.AuthorizeRequest{req("100.00")}); !errors.Is(err, policyctl.ErrVersionNotFound) {
		t.Errorf("err = %v, want ErrVersionNotFound", err)
	}
}

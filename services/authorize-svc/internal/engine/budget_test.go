package engine

import (
	"context"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func budgetPolicy() Policy {
	p := fixturePolicy()
	p.Budgets = []BudgetDecl{{ID: "monthly", Window: "month", Limit: "50000.00", Currency: "USD"}}
	return p
}

func findOb(obs []contractsv1.Obligation, typ string) (contractsv1.Obligation, bool) {
	for _, o := range obs {
		if o.Type == typ {
			return o, true
		}
	}
	return contractsv1.Obligation{}, false
}

// A non-shadow APPROVE against a budget policy attaches a signed capture_within
// obligation whose hold_ref is the decision id and expires_at = evaluated_at + TTL.
func TestAuthorize_BudgetApprovePlacesCaptureObligation(t *testing.T) {
	kr := signing.NewKeyring()
	kr.GenerateActive()
	signer, _ := kr.Signer()
	pub, _ := kr.PublicKey(signer.KeyID())
	e := NewEngine(budgetPolicy(), signer.KeyID()).WithSigner(signer).WithHoldTTL(10 * time.Minute)

	d, err := e.Authorize(context.Background(), "", baseReq(), false) // amount 1000, within limit → APPROVE
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if d.Verdict != contractsv1.VerdictApprove {
		t.Fatalf("verdict = %s, want APPROVE", d.Verdict)
	}
	ob, ok := findOb(d.Obligations, contractsv1.ObligationCaptureWithin)
	if !ok {
		t.Fatal("no capture_within obligation on a budget-affecting APPROVE")
	}
	if ob.Params["budget_id"] != "monthly" {
		t.Errorf("budget_id = %v, want monthly", ob.Params["budget_id"])
	}
	if ob.Params["hold_ref"] != d.DecisionID {
		t.Errorf("hold_ref = %v, want decision id %s", ob.Params["hold_ref"], d.DecisionID)
	}
	if got, want := ob.Params["expires_at"], "2026-08-31T12:10:00Z"; got != want {
		t.Errorf("expires_at = %v, want %s (evaluated_at + 10m)", got, want)
	}
	// The obligation is part of the signed bytes.
	if err := signing.Verify(d, pub); err != nil {
		t.Errorf("signature verify: %v", err)
	}
}

// A shadow decision never places a hold (advisory; must not reserve budget).
func TestAuthorize_ShadowBudgetApproveHasNoObligation(t *testing.T) {
	e := NewEngine(budgetPolicy(), "k")
	d, _ := e.Authorize(context.Background(), "", baseReq(), true)
	if _, ok := findOb(d.Obligations, contractsv1.ObligationCaptureWithin); ok {
		t.Error("shadow APPROVE attached a capture_within obligation; it must not")
	}
}

// A DENY places no hold even under a budget policy.
func TestAuthorize_BudgetDenyHasNoObligation(t *testing.T) {
	e := NewEngine(budgetPolicy(), "k")
	over := baseReq()
	over.Amount = "6000.00" // over the 5000 per-transaction limit → DENY
	d, _ := e.Authorize(context.Background(), "", over, false)
	if d.Verdict != contractsv1.VerdictDeny {
		t.Fatalf("verdict = %s, want DENY", d.Verdict)
	}
	if _, ok := findOb(d.Obligations, contractsv1.ObligationCaptureWithin); ok {
		t.Error("DENY attached a capture_within obligation; it must not")
	}
}

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

// fakeReserver returns a fixed outcome, to exercise how the engine folds the budget
// result into the verdict.
type fakeReserver struct{ outcome BudgetOutcome }

func (f fakeReserver) Reserve(_ context.Context, _, _ string, _ contractsv1.AuthorizeRequest, _ BudgetDecl) BudgetResult {
	return BudgetResult{Outcome: f.outcome, SpendToDate: "10.00", Limit: "50000.00", WindowKey: "2026-08"}
}

// The reserver's outcome folds into the verdict: WithinLimit→APPROVE(+hold),
// Exceeded→DENY, Unavailable→REVIEW (fail closed). Local rules already approve here.
func TestAuthorize_ReserverFoldsIntoVerdict(t *testing.T) {
	cases := []struct {
		outcome BudgetOutcome
		want    contractsv1.Verdict
		hold    bool
	}{
		{BudgetWithinLimit, contractsv1.VerdictApprove, true},
		{BudgetExceeded, contractsv1.VerdictDeny, false},
		{BudgetUnavailable, contractsv1.VerdictReview, false},
	}
	for _, c := range cases {
		e := NewEngine(budgetPolicy(), "k").WithReserver(fakeReserver{c.outcome})
		d, err := e.Authorize(context.Background(), "org1", baseReq(), false)
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		if d.Verdict != c.want {
			t.Errorf("outcome %v: verdict = %s, want %s", c.outcome, d.Verdict, c.want)
		}
		_, hasHold := findOb(d.Obligations, contractsv1.ObligationCaptureWithin)
		if hasHold != c.hold {
			t.Errorf("outcome %v: hold obligation = %v, want %v", c.outcome, hasHold, c.hold)
		}
		// A budget matched-rule is always present when a budget applied.
		if _, ok := findMatched(d.Explanation.MatchedRules, contractsv1.TypeRollingBudget); !ok {
			t.Errorf("outcome %v: no rolling_budget matched rule", c.outcome)
		}
	}
}

func findMatched(rules []contractsv1.MatchedRule, typ contractsv1.PredicateType) (contractsv1.MatchedRule, bool) {
	for _, r := range rules {
		if r.Type == typ {
			return r, true
		}
	}
	return contractsv1.MatchedRule{}, false
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

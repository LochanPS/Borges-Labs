package engine

import (
	"testing"
	"time"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// mkInput builds an Input with a parsed amount and a fixed evaluated_at.
func mkInput(amount, currency, jurisdiction, action string, target contractsv1.Target, at time.Time) Input {
	amt, _ := parseMoney(amount)
	return Input{
		AgentID:      "agent-1",
		Action:       action,
		AmountRaw:    amount,
		Amount:       amt,
		Currency:     currency,
		Target:       target,
		Jurisdiction: jurisdiction,
		EvaluatedAt:  at,
	}
}

func vendor(id string) contractsv1.Target {
	return contractsv1.Target{Type: contractsv1.TargetVendor, ID: id}
}

func wantOutcome(t *testing.T, got Result, want Outcome) {
	t.Helper()
	if got.Outcome != want {
		t.Fatalf("outcome = %q, want %q (reason: %s)", got.Outcome, want, got.Reason)
	}
	if got.Reason == "" {
		t.Error("empty reason")
	}
	if got.Evidence == nil {
		t.Error("nil evidence")
	}
}

func TestPerTransactionLimit(t *testing.T) {
	p := PerTransactionLimit{base: base{ID: "limit"}, MaxRaw: "5000.00", Currency: "USD"}
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)

	// Under limit -> satisfied.
	wantOutcome(t, p.Evaluate(mkInput("4999.99", "USD", "", "pay", vendor("v"), at)), Satisfied)
	// Exactly at limit -> satisfied (<=).
	wantOutcome(t, p.Evaluate(mkInput("5000.00", "USD", "", "pay", vendor("v"), at)), Satisfied)
	// Over limit -> denied, with numbers in evidence.
	r := p.Evaluate(mkInput("5000.01", "USD", "", "pay", vendor("v"), at))
	wantOutcome(t, r, Denied)
	if r.Evidence["amount"] != "5000.01" || r.Evidence["limit"] != "5000.00" {
		t.Errorf("evidence missing amount/limit: %+v", r.Evidence)
	}
	// Currency mismatch -> review.
	wantOutcome(t, p.Evaluate(mkInput("10.00", "EUR", "", "pay", vendor("v"), at)), Flagged)
}

func TestVendorAllowlist(t *testing.T) {
	p := VendorAllowlist{base: base{ID: "allow"}, Vendors: []string{"acme", "globex"}}
	at := time.Now().UTC()

	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("acme"), at)), Satisfied)
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("evilcorp"), at)), Denied)
	// Non-vendor target is out of scope -> satisfied.
	acct := contractsv1.Target{Type: contractsv1.TargetAccount, ID: "a1"}
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", acct, at)), Satisfied)
}

func TestVendorBlocklist(t *testing.T) {
	p := VendorBlocklist{base: base{ID: "block"}, Vendors: []string{"evilcorp"}}
	at := time.Now().UTC()

	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("evilcorp"), at)), Denied)
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("acme"), at)), Satisfied)
}

func TestAgentPermission(t *testing.T) {
	p := AgentPermission{base: base{ID: "perm"}, AllowedActions: []string{"payment.create"}, AllowedTargets: []string{"acme"}}
	at := time.Now().UTC()

	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "payment.create", vendor("acme"), at)), Satisfied)
	// Disallowed action.
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "payment.refund", vendor("acme"), at)), Denied)
	// Disallowed target.
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "payment.create", vendor("globex"), at)), Denied)
}

func TestTimeWindow(t *testing.T) {
	// Business hours 09:00-17:00 UTC, weekdays Mon-Fri.
	p := TimeWindow{base: base{ID: "hours"}, StartMinute: 9 * 60, EndMinute: 17 * 60,
		Weekdays: []int{1, 2, 3, 4, 5}}

	inside := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC) // Monday noon
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), inside)), Satisfied)

	tooEarly := time.Date(2026, 8, 31, 8, 59, 0, 0, time.UTC)
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), tooEarly)), Denied)

	weekend := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC) // Sunday
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), weekend)), Denied)

	// Window that wraps midnight: 22:00-06:00.
	night := TimeWindow{base: base{ID: "night"}, StartMinute: 22 * 60, EndMinute: 6 * 60}
	wantOutcome(t, night.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), time.Date(2026, 8, 31, 23, 0, 0, 0, time.UTC))), Satisfied)
	wantOutcome(t, night.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC))), Denied)
}

func TestJurisdictionCurrency(t *testing.T) {
	p := JurisdictionCurrency{base: base{ID: "juris"}, Allowed: map[string][]string{
		"US": {"USD"}, "EU": {"EUR", "USD"},
	}}
	at := time.Now().UTC()

	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "US", "pay", vendor("v"), at)), Satisfied)
	wantOutcome(t, p.Evaluate(mkInput("1.00", "GBP", "US", "pay", vendor("v"), at)), Denied)
	// Unconstrained jurisdiction passes.
	wantOutcome(t, p.Evaluate(mkInput("1.00", "JPY", "JP", "pay", vendor("v"), at)), Satisfied)
	// Empty jurisdiction passes.
	wantOutcome(t, p.Evaluate(mkInput("1.00", "USD", "", "pay", vendor("v"), at)), Satisfied)
}

func TestAppliesTo(t *testing.T) {
	scoped := base{ID: "x", Agents: []string{"a", "b"}}
	if !scoped.AppliesTo("a") || scoped.AppliesTo("c") {
		t.Error("agent scoping wrong")
	}
	global := base{ID: "y"}
	if !global.AppliesTo("anyone") {
		t.Error("empty scope should apply to all")
	}
}

package policyctl

import (
	"errors"
	"strings"
	"testing"
)

func i(n int) *int { return &n }

// A policy exercising all nine rule types (six local + three placeholders) is valid.
func TestValidate_AllNineTypes(t *testing.T) {
	rules := []Rule{
		{ID: "a", Type: "per_transaction_limit", Max: "100.00", Currency: "USD"},
		{ID: "b", Type: "vendor_allowlist", Vendors: []string{"acme"}},
		{ID: "c", Type: "vendor_blocklist", Vendors: []string{"evil"}},
		{ID: "d", Type: "agent_permission", AllowedActions: []string{"payment.create"}},
		{ID: "e", Type: "time_window", StartMinute: i(540), EndMinute: i(1020), Weekdays: []int{1, 2, 3, 4, 5}},
		{ID: "f", Type: "jurisdiction_currency", Allowed: map[string][]string{"US": {"USD"}}},
		{ID: "g", Type: "rolling_budget", Window: "month", Limit: "50000.00"},
		{ID: "h", Type: "sanctions_screen", Provider: "acme-screen", FailMode: "fail_closed"},
		{ID: "i", Type: "vendor_risk", Provider: "acme-risk", Threshold: i(80), FailMode: "fail_closed"},
	}
	if err := Validate("org1", "everything", nil, rules); err != nil {
		t.Fatalf("all-types policy rejected: %v", err)
	}
}

func TestValidate_Rejections(t *testing.T) {
	cases := map[string][]Rule{
		"missing max":          {{ID: "a", Type: "per_transaction_limit"}},
		"empty allowlist":      {{ID: "a", Type: "vendor_allowlist", Vendors: []string{}}},
		"permission needs one": {{ID: "a", Type: "agent_permission"}},
		"time out of range":    {{ID: "a", Type: "time_window", StartMinute: i(0), EndMinute: i(2000)}},
		"weekday out of range": {{ID: "a", Type: "time_window", StartMinute: i(0), EndMinute: i(60), Weekdays: []int{9}}},
		"unknown type":         {{ID: "a", Type: "wormhole"}},
		"field not for type":   {{ID: "a", Type: "vendor_blocklist", Vendors: []string{"x"}, Max: "5"}},
		"bad currency":         {{ID: "a", Type: "per_transaction_limit", Max: "5", Currency: "usd"}},
		"budget bad window":    {{ID: "a", Type: "rolling_budget", Window: "fortnight", Limit: "5"}},
		"bad fail_mode":        {{ID: "a", Type: "sanctions_screen", FailMode: "maybe"}},
		"jurisdiction bad key": {{ID: "a", Type: "jurisdiction_currency", Allowed: map[string][]string{"USA": {"USD"}}}},
	}
	for name, rules := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Validate("org1", "p", nil, rules); err == nil {
				t.Errorf("Validate(%s) = nil, want rejection", name)
			}
		})
	}
}

func TestValidate_MissingIdentity(t *testing.T) {
	rules := []Rule{{ID: "a", Type: "vendor_blocklist", Vendors: []string{"x"}}}
	if err := Validate("", "p", nil, rules); err == nil {
		t.Error("missing org_id accepted")
	}
	if err := Validate("org1", "", nil, rules); err == nil {
		t.Error("missing name accepted")
	}
}

func TestValidate_EmptyRulesRejected(t *testing.T) {
	if err := Validate("org1", "p", nil, nil); err == nil {
		t.Error("empty ruleset accepted; schema requires at least one rule")
	}
}

// A validation error names the offending field so a policy owner can fix it.
func TestValidationError_HasPointers(t *testing.T) {
	err := Validate("org1", "p", nil, []Rule{{ID: "a", Type: "per_transaction_limit"}})
	if err == nil {
		t.Fatal("expected rejection")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("type = %T, want *ValidationError", err)
	}
	found := false
	for _, p := range ve.Problems {
		if strings.HasPrefix(p.Pointer, "/rules/0") {
			found = true
		}
	}
	if !found {
		t.Errorf("no problem pointed at /rules/0: %+v", ve.Problems)
	}
}

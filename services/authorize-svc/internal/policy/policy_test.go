package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/engine"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func approve(t *testing.T, pol engine.Policy, req contractsv1.AuthorizeRequest) contractsv1.Decision {
	t.Helper()
	dec, err := engine.NewEngine(pol, "test-key").Authorize(context.Background(), req)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	return dec
}

// The embedded default policy must load, be non-empty, and APPROVE an ordinary
// in-limit payment while DENYing an over-limit one and a disallowed action.
func TestDefault_LoadsAndDecides(t *testing.T) {
	pol, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if len(pol.Predicates) == 0 {
		t.Fatal("default policy has no predicates")
	}
	if !strings.HasPrefix(pol.Version, "pol_") {
		t.Errorf("version = %q, want pol_ prefix", pol.Version)
	}

	ok := contractsv1.AuthorizeRequest{
		AgentID: "a", Action: "payment.create", Amount: "500.00", Currency: "USD",
		Target: contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
	}
	if v := approve(t, pol, ok).Verdict; v != contractsv1.VerdictApprove {
		t.Errorf("in-limit payment verdict = %q, want APPROVE", v)
	}

	over := ok
	over.Amount = "10000.01"
	if v := approve(t, pol, over).Verdict; v != contractsv1.VerdictDeny {
		t.Errorf("over-limit verdict = %q, want DENY", v)
	}

	badAction := ok
	badAction.Action = "wire.transfer"
	if v := approve(t, pol, badAction).Verdict; v != contractsv1.VerdictDeny {
		t.Errorf("disallowed action verdict = %q, want DENY", v)
	}
}

// Every local predicate type parses into the right engine predicate.
func TestParse_AllPredicateTypes(t *testing.T) {
	raw := []byte(`{
	  "version": "pol_fixed_v1",
	  "predicates": [
	    {"id":"lim","type":"per_transaction_limit","max":"100.00","currency":"USD"},
	    {"id":"allow","type":"vendor_allowlist","vendors":["acme"]},
	    {"id":"block","type":"vendor_blocklist","vendors":["evilcorp"]},
	    {"id":"perm","type":"agent_permission","allowed_actions":["payment.create"]},
	    {"id":"hours","type":"time_window","start_minute":540,"end_minute":1020,"weekdays":[1,2,3,4,5]},
	    {"id":"juris","type":"jurisdiction_currency","allowed":{"US":["USD"]}}
	  ]
	}`)
	pol, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pol.Version != "pol_fixed_v1" {
		t.Errorf("version = %q, want the explicit pol_fixed_v1", pol.Version)
	}
	if len(pol.Predicates) != 6 {
		t.Fatalf("predicates = %d, want 6", len(pol.Predicates))
	}
	wantTypes := []contractsv1.PredicateType{
		contractsv1.TypePerTransactionLimit, contractsv1.TypeVendorAllowlist,
		contractsv1.TypeVendorBlocklist, contractsv1.TypeAgentPermission,
		contractsv1.TypeTimeWindow, contractsv1.TypeJurisdictionCurrency,
	}
	for i, p := range pol.Predicates {
		if p.Type() != wantTypes[i] {
			t.Errorf("predicate[%d] type = %q, want %q", i, p.Type(), wantTypes[i])
		}
	}
}

// Identical policies (differing only in key order/whitespace) get the same content
// version; a changed value changes the version.
func TestParse_ContentVersionStableAndSensitive(t *testing.T) {
	a := []byte(`{"predicates":[{"id":"lim","type":"per_transaction_limit","max":"100.00"}]}`)
	b := []byte(`{ "predicates": [ { "type":"per_transaction_limit", "id":"lim", "max":"100.00" } ] }`)
	c := []byte(`{"predicates":[{"id":"lim","type":"per_transaction_limit","max":"200.00"}]}`)

	pa, _ := Parse(a)
	pb, _ := Parse(b)
	pc, _ := Parse(c)

	if pa.Version != pb.Version {
		t.Errorf("reordered/whitespace policies got different versions: %s vs %s", pa.Version, pb.Version)
	}
	if pa.Version == pc.Version {
		t.Error("changed limit did not change the content version")
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]string{
		"unknown type":       `{"predicates":[{"id":"x","type":"nope"}]}`,
		"enriched type":      `{"predicates":[{"id":"x","type":"rolling_budget"}]}`,
		"missing id":         `{"predicates":[{"type":"per_transaction_limit","max":"1"}]}`,
		"duplicate id":       `{"predicates":[{"id":"d","type":"vendor_blocklist"},{"id":"d","type":"vendor_blocklist"}]}`,
		"limit without max":  `{"predicates":[{"id":"x","type":"per_transaction_limit"}]}`,
		"unknown field":      `{"predicates":[{"id":"x","type":"vendor_blocklist","surprise":true}]}`,
		"allowlist empty":    `{"predicates":[{"id":"x","type":"vendor_allowlist","vendors":[]}]}`,
		"time missing bound": `{"predicates":[{"id":"x","type":"time_window","start_minute":10}]}`,
		"time out of range":  `{"predicates":[{"id":"x","type":"time_window","start_minute":0,"end_minute":2000}]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Errorf("Parse(%s) = nil error, want rejection", name)
			}
		})
	}
}

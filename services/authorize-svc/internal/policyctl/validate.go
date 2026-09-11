package policyctl

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/trust-infra/authorize-svc/internal/policy"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// schemaJSON is the frozen policy schema (a copy of contracts/schemas/policy.schema.json,
// embedded so validation has no filesystem dependency). A drift test asserts the two
// are byte-identical.
//
//go:embed policy.schema.json
var schemaJSON []byte

// compiledSchema is the parsed schema, compiled once at package init.
var compiledSchema = mustCompileSchema()

func mustCompileSchema() *jsonschema.Schema {
	c := jsonschema.NewCompiler()
	if err := c.AddResource("policy.schema.json", bytes.NewReader(schemaJSON)); err != nil {
		panic(fmt.Sprintf("policyctl: add schema resource: %v", err))
	}
	s, err := c.Compile("policy.schema.json")
	if err != nil {
		panic(fmt.Sprintf("policyctl: compile schema: %v", err))
	}
	return s
}

// localRuleTypes is the set of rule types the decision engine evaluates today. The
// other three (rolling_budget, sanctions_screen, vendor_risk) are valid to author but
// not yet enforced (Phase 3 / enrichment).
var localRuleTypes = map[string]bool{
	string(contractsv1.TypePerTransactionLimit):  true,
	string(contractsv1.TypeVendorAllowlist):      true,
	string(contractsv1.TypeVendorBlocklist):      true,
	string(contractsv1.TypeAgentPermission):      true,
	string(contractsv1.TypeTimeWindow):           true,
	string(contractsv1.TypeJurisdictionCurrency): true,
}

// enrichedRuleTypes is the set of placeholder types accepted for authoring/versioning
// but not enforced by the local engine.
var enrichedRuleTypes = map[string]bool{
	string(contractsv1.TypeRollingBudget):   true,
	string(contractsv1.TypeSanctionsScreen): true,
	string(contractsv1.TypeVendorRisk):      true,
}

// ValidationError is a policy that failed validation, carrying every problem found
// (not just the first) so a policy owner can fix them in one pass. Its Error() is a
// clear, multi-line message; Problems is the machine-readable list a control-plane
// API surfaces as RFC 7807 validation items (Task 2.2).
type ValidationError struct {
	Problems []Problem
}

// Problem is one field-level validation failure. Pointer is a JSON-pointer-ish path
// into the document (e.g. "/rules/2/max").
type Problem struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

func (e *ValidationError) Error() string {
	if len(e.Problems) == 0 {
		return "policy is invalid"
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("policy is invalid (%d problem(s)):", len(e.Problems)))
	for _, p := range e.Problems {
		b.WriteString("\n  ")
		if p.Pointer != "" {
			b.WriteString(p.Pointer)
			b.WriteString(": ")
		}
		b.WriteString(p.Detail)
	}
	return b.String()
}

// Validate checks a policy's identity and rules against the frozen schema and the
// semantic rules the schema cannot express (unique rule ids, and engine-loader parity
// for the local subset). It returns a *ValidationError with every problem found, or
// nil when the policy is publishable. Placeholder (enriched) rule types are accepted.
func Validate(orgID, name string, agents []string, rules []Rule) error {
	var problems []Problem

	// Structural validation against the JSON Schema. We validate the exact wire
	// document a client would send so schema errors point at real fields.
	doc := map[string]any{"org_id": orgID, "name": name, "rules": rulesToWire(rules)}
	if agents != nil {
		doc["agents"] = agents
	}
	// Round-trip through JSON so the value tree is the plain map/slice/number/string
	// shape the validator expects (no Go structs, no json.RawMessage).
	normalized, err := roundTrip(doc)
	if err != nil {
		return &ValidationError{Problems: []Problem{{Detail: err.Error()}}}
	}
	if err := compiledSchema.Validate(normalized); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			problems = append(problems, flattenSchemaError(ve)...)
		} else {
			problems = append(problems, Problem{Detail: err.Error()})
		}
	}

	// Semantic: rule ids must be unique within the policy (the schema cannot express
	// uniqueness across sibling object fields).
	seen := make(map[string]int, len(rules))
	for i, r := range rules {
		if r.ID == "" {
			continue // the schema already flagged the empty id
		}
		if first, dup := seen[r.ID]; dup {
			problems = append(problems, Problem{
				Pointer: fmt.Sprintf("/rules/%d/id", i),
				Detail:  fmt.Sprintf("duplicate rule id %q (first used at /rules/%d)", r.ID, first),
			})
			continue
		}
		seen[r.ID] = i
	}

	// Engine parity: every LOCAL rule must be loadable by the decision plane's policy
	// loader (internal/policy). This guarantees a published version's local subset
	// will actually be servable — a policy that validates here can never be one the
	// decision node rejects at load. Enriched placeholders are excluded (the loader
	// rejects them by design) and re-checked once Phase 3 lands.
	if perr := checkEngineParity(rules); perr != nil {
		problems = append(problems, *perr)
	}

	if len(problems) > 0 {
		sortProblems(problems)
		return &ValidationError{Problems: problems}
	}
	return nil
}

// checkEngineParity marshals the local-only subset of rules into the internal/policy
// file shape and runs its loader, surfacing any rejection as a single problem. It is a
// belt-and-suspenders parity gate on top of the schema, not the primary validator.
func checkEngineParity(rules []Rule) *Problem {
	local := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if localRuleTypes[r.Type] {
			local = append(local, r)
		}
	}
	if len(local) == 0 {
		return nil
	}
	raw, err := json.Marshal(map[string]any{"predicates": rulesToWire(local)})
	if err != nil {
		return &Problem{Detail: fmt.Sprintf("engine parity marshal: %v", err)}
	}
	if _, err := policy.Parse(raw); err != nil {
		return &Problem{Pointer: "/rules", Detail: "decision engine would reject the local rules: " + err.Error()}
	}
	return nil
}

// rulesToWire marshals rules to their plain wire objects (omitempty applied), so both
// the schema validator and the engine-parity loader see the exact JSON a client sends.
func rulesToWire(rules []Rule) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		b, _ := json.Marshal(r)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		out = append(out, m)
	}
	return out
}

func roundTrip(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal document: %w", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("unmarshal document: %w", err)
	}
	return out, nil
}

// flattenSchemaError turns the validator's nested error tree into a flat list of
// leaf problems with instance-location pointers. Leaf causes (deepest, most specific)
// carry the actionable message; oneOf branch noise is collapsed to the leaves.
func flattenSchemaError(ve *jsonschema.ValidationError) []Problem {
	var out []Problem
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(e.Causes) == 0 {
			out = append(out, Problem{
				Pointer: e.InstanceLocation,
				Detail:  e.Message,
			})
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	if len(out) == 0 {
		out = append(out, Problem{Pointer: ve.InstanceLocation, Detail: ve.Message})
	}
	return out
}

func sortProblems(ps []Problem) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Pointer != ps[j].Pointer {
			return ps[i].Pointer < ps[j].Pointer
		}
		return ps[i].Detail < ps[j].Detail
	})
}

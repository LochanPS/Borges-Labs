// Package policy loads a decision policy from JSON into an engine.Policy.
//
// A2#2 (ROADMAP): for MVP there is no separate policy-svc — a policy is loaded as
// a JSON file directly by authorize-svc (GitOps-friendly: the file can live in the
// customer's repo, PR-reviewed). Phase 2 replaces this with a published,
// content-hashed bundle from the control plane; the engine.Policy it produces is
// identical, so only the loader changes.
//
// The file is a discriminated list of the six LOCAL predicate types (Task 1.4).
// Enriched/stateful types (rolling_budget, sanctions_screen, vendor_risk) are NOT
// loadable here — they belong to Phase 3/enrichment and are rejected with a clear
// error rather than silently ignored.
//
// policy_version_hash: if the file sets "version" it is used verbatim; otherwise a
// deterministic content hash (pol_ + sha256 over the RFC 8785 JCS form of the
// normalized predicate set) is computed, so the same policy always cites the same
// version regardless of key order or whitespace.
package policy

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gowebpki/jcs"

	"github.com/trust-infra/authorize-svc/internal/engine"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

//go:embed default.policy.json
var embedded embed.FS

// versionPrefix labels a policy version so it is self-describing (matches the
// pol_ convention used across the contract).
const versionPrefix = "pol_"

// file is the on-disk shape: an optional explicit version and the predicate list.
type file struct {
	Version    string         `json:"version"`
	Predicates []predicateDoc `json:"predicates"`
}

// predicateDoc is the union of every local predicate's fields, discriminated by
// Type. Only the fields relevant to a given Type are read; unknown JSON keys are
// rejected (DisallowUnknownFields) so a typo fails loudly instead of silently.
type predicateDoc struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"`
	Agents []string `json:"agents,omitempty"` // empty = every agent

	// per_transaction_limit
	Max      string `json:"max,omitempty"`
	Currency string `json:"currency,omitempty"`

	// vendor_allowlist / vendor_blocklist
	Vendors []string `json:"vendors,omitempty"`

	// agent_permission
	AllowedActions []string `json:"allowed_actions,omitempty"`
	AllowedTargets []string `json:"allowed_targets,omitempty"`

	// time_window
	StartMinute *int  `json:"start_minute,omitempty"`
	EndMinute   *int  `json:"end_minute,omitempty"`
	Weekdays    []int `json:"weekdays,omitempty"`

	// jurisdiction_currency
	Allowed map[string][]string `json:"allowed,omitempty"`
}

// Default returns the policy shipped with the binary (embedded default.policy.json).
// It is the fallback when no AUTHZ_POLICY_FILE is configured, so the service always
// boots with a sane, non-empty policy rather than deny-by-default everything.
func Default() (engine.Policy, error) {
	b, err := embedded.ReadFile("default.policy.json")
	if err != nil {
		return engine.Policy{}, fmt.Errorf("policy: read embedded default: %w", err)
	}
	p, err := Parse(b)
	if err != nil {
		return engine.Policy{}, fmt.Errorf("policy: parse embedded default: %w", err)
	}
	return p, nil
}

// Load reads and parses a policy JSON file from disk.
func Load(path string) (engine.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return engine.Policy{}, fmt.Errorf("policy: read %s: %w", path, err)
	}
	p, err := Parse(b)
	if err != nil {
		return engine.Policy{}, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	return p, nil
}

// Parse builds an engine.Policy from policy JSON bytes, validating every predicate.
func Parse(raw []byte) (engine.Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f file
	if err := dec.Decode(&f); err != nil {
		return engine.Policy{}, fmt.Errorf("decode policy: %w", err)
	}

	preds := make([]engine.Predicate, 0, len(f.Predicates))
	seen := make(map[string]bool, len(f.Predicates))
	for i, d := range f.Predicates {
		if d.ID == "" {
			return engine.Policy{}, fmt.Errorf("predicate[%d]: id is required", i)
		}
		if seen[d.ID] {
			return engine.Policy{}, fmt.Errorf("predicate[%d]: duplicate id %q", i, d.ID)
		}
		seen[d.ID] = true

		p, err := d.build()
		if err != nil {
			return engine.Policy{}, fmt.Errorf("predicate %q (%s): %w", d.ID, d.Type, err)
		}
		preds = append(preds, p)
	}

	version := f.Version
	if version == "" {
		v, err := contentVersion(f.Predicates)
		if err != nil {
			return engine.Policy{}, err
		}
		version = v
	}
	return engine.Policy{Version: version, Predicates: preds}, nil
}

// build maps one predicateDoc to its concrete engine.Predicate, validating the
// fields that type requires.
func (d predicateDoc) build() (engine.Predicate, error) {
	switch contractsv1.PredicateType(d.Type) {
	case contractsv1.TypePerTransactionLimit:
		if d.Max == "" {
			return nil, fmt.Errorf("max is required")
		}
		return engine.NewPerTransactionLimit(d.ID, d.Agents, d.Max, d.Currency), nil

	case contractsv1.TypeVendorAllowlist:
		if len(d.Vendors) == 0 {
			return nil, fmt.Errorf("vendors must be non-empty")
		}
		return engine.NewVendorAllowlist(d.ID, d.Agents, d.Vendors), nil

	case contractsv1.TypeVendorBlocklist:
		return engine.NewVendorBlocklist(d.ID, d.Agents, d.Vendors), nil

	case contractsv1.TypeAgentPermission:
		if len(d.AllowedActions) == 0 && len(d.AllowedTargets) == 0 {
			return nil, fmt.Errorf("at least one of allowed_actions or allowed_targets is required")
		}
		return engine.NewAgentPermission(d.ID, d.Agents, d.AllowedActions, d.AllowedTargets), nil

	case contractsv1.TypeTimeWindow:
		if d.StartMinute == nil || d.EndMinute == nil {
			return nil, fmt.Errorf("start_minute and end_minute are required")
		}
		if err := validMinute(*d.StartMinute); err != nil {
			return nil, fmt.Errorf("start_minute: %w", err)
		}
		if err := validMinute(*d.EndMinute); err != nil {
			return nil, fmt.Errorf("end_minute: %w", err)
		}
		for _, wd := range d.Weekdays {
			if wd < 0 || wd > 6 {
				return nil, fmt.Errorf("weekday %d out of range (0=Sunday..6=Saturday)", wd)
			}
		}
		return engine.NewTimeWindow(d.ID, d.Agents, *d.StartMinute, *d.EndMinute, d.Weekdays), nil

	case contractsv1.TypeJurisdictionCurrency:
		if len(d.Allowed) == 0 {
			return nil, fmt.Errorf("allowed map must be non-empty")
		}
		return engine.NewJurisdictionCurrency(d.ID, d.Agents, d.Allowed), nil

	case contractsv1.TypeRollingBudget, contractsv1.TypeSanctionsScreen, contractsv1.TypeVendorRisk:
		return nil, fmt.Errorf("predicate type %q is enriched/stateful and not supported by the local engine (Phase 3/enrichment)", d.Type)

	case "":
		return nil, fmt.Errorf("type is required")
	default:
		return nil, fmt.Errorf("unknown predicate type %q", d.Type)
	}
}

func validMinute(m int) error {
	if m < 0 || m >= 1440 {
		return fmt.Errorf("must be in [0,1440), got %d", m)
	}
	return nil
}

// contentVersion computes a deterministic pol_ version from the predicate set: the
// RFC 8785 JCS canonical form of the docs, SHA-256'd. Independent of key order and
// whitespace, so two byte-different-but-equal policies share a version.
func contentVersion(docs []predicateDoc) (string, error) {
	raw, err := json.Marshal(docs)
	if err != nil {
		return "", fmt.Errorf("policy: marshal for version: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("policy: canonicalize for version: %w", err)
	}
	sum := sha256.Sum256(canon)
	return versionPrefix + hex.EncodeToString(sum[:]), nil
}

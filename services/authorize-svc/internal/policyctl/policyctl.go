// Package policyctl is the MVP control plane for authorization policies: authoring,
// validation, immutable content-hash versioning, and Ed25519 signing of published
// versions (ROADMAP Task 2.1, TRD §6).
//
// Where this lives. TRD §3 names a separate policy-svc. ROADMAP A2#2 defers standing
// up that second (Node) runtime until the dashboard lands (Phase 5) and, for MVP,
// folds the control-plane logic into the Go service as thin, self-contained pieces.
// This package IS that fold: pure domain logic (validate → hash → sign → store) with
// a Store seam (Postgres + in-memory), no HTTP. The /v1/policies endpoints and bundle
// propagation to decision nodes are Task 2.2; they will wire handlers over this
// Service without changing it. The decision plane still never calls the control plane
// synchronously (TRD §3 boundary rule) — it loads a policy file today (internal/policy)
// and, in Task 2.2, a published, cached bundle.
//
// No compiler (ROADMAP A#6). For the nine JSON rule types "compile" means exactly:
// validate against policy.schema.json, canonicalize, content-hash, and sign. Nothing
// is transformed into another representation.
//
// What is enforced today. The six LOCAL rule types (Task 1.4) are evaluated by the
// decision engine now. rolling_budget / sanctions_screen / vendor_risk are valid to
// author, version, and sign (they are part of the policy the org owns) but the current
// local engine rejects them at load (internal/policy) — Phase 3 / enrichment adds their
// evaluation. Validation here therefore accepts all nine while also proving, for the
// local subset, that the decision plane's loader would accept it (engine parity).
package policyctl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Canonicalization is the scheme id stamped on a policy version's signature and
// documented in docs/policy-schema.md. It is distinct from the decision receipt's
// scheme (ti-decision-canon/1): a verifier selects behavior by this value. Bump it
// (/2, …) on any change to the signed field set or serialization rules.
const Canonicalization = "ti-policy-canon/1"

// versionPrefix labels a published policy version hash so it is self-describing and
// unambiguous next to the decision plane's local content hash (internal/policy uses
// pol_). A published version binds identity (org, policy, name, agents) to content.
const versionPrefix = "polv_"

// Status is a policy's lifecycle state. A policy is draft until its first successful
// publish, then published; editing the working copy does not revert it (the active
// version keeps serving until a republish).
type Status string

const (
	StatusDraft     Status = "draft"
	StatusPublished Status = "published"
)

// Rule is one typed rule in a policy document. It is the union of every rule type's
// fields, discriminated by Type, mirroring the wire shape in policy.schema.json and
// the six-local-type doc in internal/policy so a published version's local subset is
// loadable by the decision plane verbatim. Only the fields relevant to a Type are
// meaningful; validation rejects fields that do not belong to the Type.
type Rule struct {
	ID     string   `json:"id"`
	Type   string   `json:"type"`
	Agents []string `json:"agents,omitempty"`

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

	// rolling_budget (placeholder, Phase 3)
	Window string `json:"window,omitempty"`
	Limit  string `json:"limit,omitempty"`

	// sanctions_screen / vendor_risk (placeholder, enrichment)
	Provider  string `json:"provider,omitempty"`
	Threshold *int   `json:"threshold,omitempty"`
	FailMode  string `json:"fail_mode,omitempty"`
}

// Policy is the mutable working copy of an org's policy — the authoring surface.
// Edits mutate it; Publish snapshots it into an immutable Version. ActiveVersionHash
// names the version currently designated to serve (what the decision plane converges
// to in Task 2.2); it is empty until the first publish.
type Policy struct {
	ID                string    `json:"id"`
	OrgID             string    `json:"org_id"`
	Name              string    `json:"name"`
	Agents            []string  `json:"agents"`
	Rules             []Rule    `json:"rules"`
	Status            Status    `json:"status"`
	ActiveVersionHash string    `json:"active_version_hash,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// BundleRef names the single published version currently serving an org's decision
// plane (the "active bundle" — Task 2.2, one-active-per-org MVP model). Publishing or
// rolling back a policy points the org's bundle at that version; the decision plane
// converges to it (immediately in-process, within the refresh TTL across instances)
// and every decision cites its VersionHash. GET /v1/policies/active returns this.
type BundleRef struct {
	OrgID       string    `json:"org_id"`
	PolicyID    string    `json:"policy_id"`
	VersionHash string    `json:"version_hash"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Version is an immutable, content-addressed, signed snapshot of a policy at publish
// time. VersionHash is a pure function of the signed content (identity + rules), so
// identical content always yields the same hash (republishing is idempotent) and any
// edit yields a new hash. ParentHash records which version was active when this one
// was published, giving the version history a lineage independent of wall-clock order.
type Version struct {
	VersionHash string                `json:"version_hash"`
	PolicyID    string                `json:"policy_id"`
	OrgID       string                `json:"org_id"`
	Name        string                `json:"name"`
	Agents      []string              `json:"agents"`
	Rules       []Rule                `json:"rules"`
	Signature   contractsv1.Signature `json:"signature"`
	Author      string                `json:"author"`
	ParentHash  string                `json:"parent_hash,omitempty"`
	PublishedAt time.Time             `json:"published_at"`
}

// signedView is the exact, ordered field set folded into the version hash and covered
// by the signature. It binds the policy's identity to its rules so a version hash is
// unique to this policy's content (not shared across policies that happen to share a
// ruleset) and so a signature cannot be lifted onto a different policy. Excludes
// server-assigned/mutable fields (author, published_at, parent_hash, status).
type signedView struct {
	PolicyID string   `json:"policy_id"`
	OrgID    string   `json:"org_id"`
	Name     string   `json:"name"`
	Agents   []string `json:"agents"`
	Rules    []Rule   `json:"rules"`
}

// CanonicalMessage returns the exact bytes hashed and signed for a version, per
// docs/policy-schema.md. Pure function of the signed fields (RFC 8785 JCS), so signer
// and any third-party verifier produce identical bytes regardless of key order.
func CanonicalMessage(policyID, orgID, name string, agents []string, rules []Rule) ([]byte, error) {
	v := signedView{
		PolicyID: policyID,
		OrgID:    orgID,
		Name:     name,
		Agents:   agents,
		Rules:    rules,
	}
	// Normalize empty slices to [] (never null): null and [] are different JCS bytes.
	if v.Agents == nil {
		v.Agents = []string{}
	}
	if v.Rules == nil {
		v.Rules = []Rule{}
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("policyctl: marshal signed view: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("policyctl: canonicalize signed view: %w", err)
	}
	return canon, nil
}

// ContentHash returns the immutable version hash for the given content: the JCS
// canonical form of the signed view, SHA-256'd, prefixed. Independent of key order
// and whitespace.
func ContentHash(policyID, orgID, name string, agents []string, rules []Rule) (string, error) {
	msg, err := CanonicalMessage(policyID, orgID, name, agents, rules)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return versionPrefix + hex.EncodeToString(sum[:]), nil
}

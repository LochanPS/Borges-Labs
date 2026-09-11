// Package audit is the append-only, tamper-evident decision log (TRD §12–14,
// ROADMAP Task 1.6, A#10).
//
// Every decision the engine returns is persisted here ASYNCHRONOUSLY, off the
// request's hot path — the write must never add to the response's latency_ms. Two
// integrity mechanisms protect the log, both verifiable by a third party:
//
//   - Hash chain. Each record links to the previous record for its org via
//     record_hash = H(prev_hash ‖ canonical(record)), so mutating any stored field
//     breaks the recomputed hash and rewriting a hash breaks the next record's link.
//   - Ed25519 signature. The Decision carries the asymmetric signature the signing
//     package produced; a reader re-verifies it against the published public key.
//
// GET /v1/decisions/{id} recomputes BOTH at read time and reports the combined
// result as signature_verified (decision.schema.json).
//
// Sensitive request fields (amount, target) are encrypted at rest (A#10) via the
// Encryptor seam; the hash is always computed over PLAINTEXT so it stays
// independently reproducible. Non-sensitive filter fields stay plaintext.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// GenesisPrev is the prev_hash of the first record in an org's chain. A fixed,
// documented sentinel so a verifier can recognize the chain's start.
const GenesisPrev = "rh_genesis/1"

// recordHashPrefix labels the hash so it is self-describing in logs and responses.
const recordHashPrefix = "rh_"

// Record is one persisted decision plus its request-derived envelope and chain
// links. In memory the sensitive fields (Amount, TargetType, TargetID) are always
// PLAINTEXT; encryption happens only at the storage boundary.
type Record struct {
	Seq        int64 // storage-assigned insertion order (0 until persisted)
	DecisionID string
	OrgID      string
	APIKeyID   string

	// request-derived
	AgentID      string
	Action       string
	Amount       string // sensitive (A#10)
	Currency     string
	TargetType   string // sensitive (A#10)
	TargetID     string // sensitive (A#10) — the counterparty
	Jurisdiction string

	// decision content (the signed receipt)
	Verdict           contractsv1.Verdict
	PolicyVersionHash string
	Explanation       contractsv1.Explanation
	Obligations       []contractsv1.Obligation
	Signature         contractsv1.Signature
	LatencyMs         int
	EvaluatedAt       string
	Shadow            bool

	// chain + lifecycle
	PrevHash    string
	RecordHash  string
	RetainUntil time.Time
	CreatedAt   time.Time
}

// RecordFromDecision builds a Record from the request that was authorized, the
// authenticated caller, and the signed Decision. It does not compute the hash or
// chain links — the Store assigns those atomically at append time.
func RecordFromDecision(orgID, apiKeyID string, req contractsv1.AuthorizeRequest, dec contractsv1.Decision) *Record {
	obs := dec.Obligations
	if obs == nil {
		obs = []contractsv1.Obligation{}
	}
	if dec.Explanation.MatchedRules == nil {
		dec.Explanation.MatchedRules = []contractsv1.MatchedRule{}
	}
	return &Record{
		DecisionID:        dec.DecisionID,
		OrgID:             orgID,
		APIKeyID:          apiKeyID,
		AgentID:           req.AgentID,
		Action:            req.Action,
		Amount:            req.Amount,
		Currency:          req.Currency,
		TargetType:        string(req.Target.Type),
		TargetID:          req.Target.ID,
		Jurisdiction:      req.Jurisdiction,
		Verdict:           dec.Verdict,
		PolicyVersionHash: dec.PolicyVersionHash,
		Explanation:       dec.Explanation,
		Obligations:       obs,
		Signature:         dec.Signature,
		LatencyMs:         dec.LatencyMs,
		EvaluatedAt:       dec.EvaluatedAt,
		Shadow:            dec.Shadow,
	}
}

// Decision reconstructs the contract Decision from the stored record, including the
// record-only fields (record_hash, and signature_verified from the given result).
func (r *Record) Decision(signatureVerified bool) contractsv1.Decision {
	verified := signatureVerified
	return contractsv1.Decision{
		DecisionID:        r.DecisionID,
		Verdict:           r.Verdict,
		PolicyVersionHash: r.PolicyVersionHash,
		Explanation:       r.Explanation,
		Obligations:       r.Obligations,
		LatencyMs:         r.LatencyMs,
		EvaluatedAt:       r.EvaluatedAt,
		Signature:         r.Signature,
		Shadow:            r.Shadow,
		RecordHash:        r.RecordHash,
		SignatureVerified: &verified,
	}
}

// hashView is the exact, ordered field set folded into record_hash. It is
// serialized to RFC 8785 JCS bytes and SHA-256'd. Any change to this shape is a
// breaking change to the chain format and must be versioned in GenesisPrev.
//
// Sensitive fields appear as PLAINTEXT here (never ciphertext), so the hash is
// reproducible by any party that can decrypt the record.
type hashView struct {
	PrevHash          string                   `json:"prev_hash"`
	DecisionID        string                   `json:"decision_id"`
	OrgID             string                   `json:"org_id"`
	APIKeyID          string                   `json:"api_key_id"`
	AgentID           string                   `json:"agent_id"`
	Action            string                   `json:"action"`
	Amount            string                   `json:"amount"`
	Currency          string                   `json:"currency"`
	TargetType        string                   `json:"target_type"`
	TargetID          string                   `json:"target_id"`
	Jurisdiction      string                   `json:"jurisdiction"`
	Verdict           contractsv1.Verdict      `json:"verdict"`
	PolicyVersionHash string                   `json:"policy_version_hash"`
	Explanation       contractsv1.Explanation  `json:"explanation"`
	Obligations       []contractsv1.Obligation `json:"obligations"`
	Signature         contractsv1.Signature    `json:"signature"`
	LatencyMs         int                      `json:"latency_ms"`
	EvaluatedAt       string                   `json:"evaluated_at"`
	Shadow            bool                     `json:"shadow"`
}

// ComputeRecordHash returns the tamper-evident hash of r chained to prev. It is a
// pure function of prev and the record's fields, so signer and verifier agree.
func ComputeRecordHash(prev string, r *Record) (string, error) {
	v := hashView{
		PrevHash:          prev,
		DecisionID:        r.DecisionID,
		OrgID:             r.OrgID,
		APIKeyID:          r.APIKeyID,
		AgentID:           r.AgentID,
		Action:            r.Action,
		Amount:            r.Amount,
		Currency:          r.Currency,
		TargetType:        r.TargetType,
		TargetID:          r.TargetID,
		Jurisdiction:      r.Jurisdiction,
		Verdict:           r.Verdict,
		PolicyVersionHash: r.PolicyVersionHash,
		Explanation:       r.Explanation,
		Obligations:       r.Obligations,
		Signature:         r.Signature,
		LatencyMs:         r.LatencyMs,
		EvaluatedAt:       r.EvaluatedAt,
		Shadow:            r.Shadow,
	}
	// Normalize empty arrays to [] (never null): distinct JCS bytes otherwise.
	if v.Obligations == nil {
		v.Obligations = []contractsv1.Obligation{}
	}
	if v.Explanation.MatchedRules == nil {
		v.Explanation.MatchedRules = []contractsv1.MatchedRule{}
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("audit: marshal hash view: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize hash view: %w", err)
	}
	sum := sha256.Sum256(canon)
	return recordHashPrefix + hex.EncodeToString(sum[:]), nil
}

// VerifyChainLink reports whether r's stored RecordHash is the correct hash of its
// contents chained to its PrevHash. A false result means the row was mutated after
// it was written (or its hash was tampered).
func VerifyChainLink(r *Record) (bool, error) {
	want, err := ComputeRecordHash(r.PrevHash, r)
	if err != nil {
		return false, err
	}
	return want == r.RecordHash, nil
}

// Filter narrows a decisions listing. Zero-value fields are ignored. From is an
// inclusive lower bound and To an exclusive upper bound on evaluated_at.
type Filter struct {
	AgentID string
	Verdict contractsv1.Verdict
	From    time.Time
	To      time.Time
	Limit   int
	Cursor  int64 // seq strictly below this value (0 = newest page)
}

// Page is one page of listed records, newest first, plus the cursor to fetch the
// next page (0 when the listing is exhausted).
type Page struct {
	Records    []*Record
	NextCursor int64
}

// Store is the append-only decision log. Implementations: Postgres (source of
// truth) and an in-memory fake for hermetic tests (same seam as auth/ratelimit).
//
// Append assigns Seq, PrevHash, and RecordHash atomically so an org's chain stays
// linear and gap-free. Reads are always org-scoped: a caller can only see its own
// org's records.
type Store interface {
	Append(ctx context.Context, r *Record) error
	Get(ctx context.Context, orgID, decisionID string) (*Record, error)
	List(ctx context.Context, orgID string, f Filter) (Page, error)
}

// ErrNotFound is returned by Get when no record matches within the org.
var ErrNotFound = fmt.Errorf("audit: decision not found")

// DefaultListLimit and MaxListLimit bound a listing page (contract: 1..200, default 50).
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// clampLimit applies the contract's page-size bounds.
func clampLimit(n int) int {
	if n <= 0 {
		return DefaultListLimit
	}
	if n > MaxListLimit {
		return MaxListLimit
	}
	return n
}

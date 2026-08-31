// Package signing implements ASYMMETRIC (Ed25519) decision signing and verification
// (TRD §11, ROADMAP Task 1.5, ROADMAP A#1).
//
// A Decision is an audit receipt: the service signs it with an Ed25519 private key,
// publishes the public key (JWKS-style at GET /v1/keys/public), and ANY third party
// — customer, auditor, regulator — verifies it with no shared secret. This is
// deliberately NOT HMAC: a symmetric MAC would let any key-holder forge our
// decisions, which is unacceptable for an audit artifact.
//
// The exact bytes that are signed are defined by docs/decision-canonicalization.md
// (`ti-decision-canon/1`): an allowlisted subset of Decision fields serialized with
// RFC 8785 JSON Canonicalization Scheme (JCS). Because every monetary value in the
// contract is a decimal string (never a JSON number), JCS number formatting never
// touches money — canonicalization is fully reproducible by outside verifiers.
package signing

import (
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Canonicalization is the scheme identifier stamped on every signature and named by
// docs/decision-canonicalization.md. Bump it (to /2, …) on any change to the signed
// field set or the serialization rules; verifiers select behavior by this value.
const Canonicalization = "ti-decision-canon/1"

// Algorithm is the fixed signature algorithm for v1.
const Algorithm = "Ed25519"

// signedView is the allowlist of Decision fields that are signed (canon doc §1).
// Fields NOT here — latency_ms, signature, record_hash, signature_verified — are
// deliberately excluded. Tags carry no omitempty so the field set is exactly fixed;
// `shadow` is always present (absent is treated as false), matching the doc.
type signedView struct {
	DecisionID        string                   `json:"decision_id"`
	Verdict           contractsv1.Verdict      `json:"verdict"`
	PolicyVersionHash string                   `json:"policy_version_hash"`
	Explanation       contractsv1.Explanation  `json:"explanation"`
	Obligations       []contractsv1.Obligation `json:"obligations"`
	EvaluatedAt       string                   `json:"evaluated_at"`
	Shadow            bool                     `json:"shadow"`
}

// CanonicalMessage returns the exact bytes to sign/verify for a Decision, per
// docs/decision-canonicalization.md. It is a pure function of the signed fields, so
// signer and any third-party verifier produce identical bytes.
func CanonicalMessage(d contractsv1.Decision) ([]byte, error) {
	v := signedView{
		DecisionID:        d.DecisionID,
		Verdict:           d.Verdict,
		PolicyVersionHash: d.PolicyVersionHash,
		Explanation:       d.Explanation,
		Obligations:       d.Obligations,
		EvaluatedAt:       d.EvaluatedAt,
		Shadow:            d.Shadow,
	}
	// Normalize empty arrays to [] (never null): null and [] are different JCS bytes,
	// and the contract's arrays are always present.
	if v.Obligations == nil {
		v.Obligations = []contractsv1.Obligation{}
	}
	if v.Explanation.MatchedRules == nil {
		v.Explanation.MatchedRules = []contractsv1.MatchedRule{}
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("signing: marshal signed view: %w", err)
	}
	// jcs.Transform re-parses and re-serializes to RFC 8785 canonical form, so any
	// intermediate escaping choices by encoding/json are normalized away.
	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("signing: canonicalize: %w", err)
	}
	return canon, nil
}

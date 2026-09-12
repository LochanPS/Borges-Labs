// This file provides a PHASE-0 stub authorizer: it assembles a schema-valid
// APPROVE Decision without evaluating any policy. It exists so the HTTP layer
// (server package) has a real seam to call — the handler stays thin and the
// hardcoded verdict lives behind an interface the real engine will implement next.
//
// What is real here: id generation, the Decision shape, latency measurement, and
// echoing the orchestrator-injected evaluated_at. What is stubbed: there is no
// predicate evaluation, no counter reads, and the signature is a placeholder — the
// value is NOT a real Ed25519 signature (TRD §11 wiring lands with the signer).
package engine

import (
	"context"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	"github.com/trust-infra/authorize-svc/internal/ulid"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// signatureCanonicalization is the frozen canonicalization identifier every
// decision signature carries (contracts/schemas/common.schema.json).
const signatureCanonicalization = "ti-decision-canon/1"

// stubSignatureValue is a placeholder that satisfies the contract's base64url
// signature pattern but is NOT a real Ed25519 signature. Replaced when signing
// is wired.
const stubSignatureValue = "c3R1Yi1kZWNpc2lvbi1zaWduYXR1cmUtbm90LXlldC1yZWFs"

// Stub is a placeholder authorizer that always returns APPROVE. It implements the
// same method the real engine will, so swapping it in is a one-line change in main.
type Stub struct {
	// PolicyVersionHash is echoed onto every decision (the bundle it "evaluated").
	PolicyVersionHash string
	// SigningKeyID names the key the placeholder signature is attributed to.
	SigningKeyID string
	// Signer, when set, applies a real Ed25519 signature (Task 1.5); when nil the
	// decision carries the placeholder signature below.
	Signer *signing.Signer
}

// Authorize returns a hardcoded, schema-valid APPROVE for the given request.
//
// It stamps evaluated_at if the orchestrator has not already (clients must not set
// it — see the contract), measures its own evaluation latency, and mints a fresh
// decision id. No policy is consulted.
func (s Stub) Authorize(_ context.Context, _ string, req contractsv1.AuthorizeRequest) (contractsv1.Decision, error) {
	start := time.Now()

	evaluatedAt := req.EvaluatedAt
	if evaluatedAt == "" {
		evaluatedAt = start.UTC().Format(time.RFC3339)
	}

	dec := contractsv1.Decision{
		DecisionID:        ulid.New(),
		Verdict:           contractsv1.VerdictApprove,
		PolicyVersionHash: s.PolicyVersionHash,
		Explanation: contractsv1.Explanation{
			Summary: "Stub authorizer: APPROVE (no policy evaluated).",
			// Empty, non-nil slice — the contract requires an array, never null.
			MatchedRules: []contractsv1.MatchedRule{},
		},
		// Non-nil so it serializes as [] not null.
		Obligations: []contractsv1.Obligation{},
		EvaluatedAt: evaluatedAt,
		Signature: contractsv1.Signature{
			Algorithm:        "Ed25519",
			KeyID:            s.SigningKeyID,
			Value:            stubSignatureValue,
			Canonicalization: signatureCanonicalization,
		},
	}
	if s.Signer != nil {
		if err := s.Signer.Sign(&dec); err != nil {
			return contractsv1.Decision{}, err
		}
	}
	dec.LatencyMs = int(time.Since(start).Milliseconds())
	return dec, nil
}

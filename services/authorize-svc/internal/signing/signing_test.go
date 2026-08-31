package signing

import (
	"crypto/ed25519"
	"testing"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func sampleDecision() contractsv1.Decision {
	return contractsv1.Decision{
		DecisionID:        "01HXYZ8K3M9QF0R7S2T4V6W8XA",
		Verdict:           contractsv1.VerdictDeny,
		PolicyVersionHash: "pol_test_abc",
		Explanation: contractsv1.Explanation{
			Summary: "Denied by rule \"per_txn_limit\": amount=6000.00 exceeds limit=5000.00 USD",
			MatchedRules: []contractsv1.MatchedRule{
				{
					RuleID:   "per_txn_limit",
					Type:     contractsv1.TypePerTransactionLimit,
					Result:   contractsv1.ResultDenied,
					Detail:   "amount=6000.00 exceeds per-transaction limit=5000.00 USD",
					Evidence: map[string]interface{}{"amount": "6000.00", "limit": "5000.00", "currency": "USD"},
				},
			},
		},
		Obligations: []contractsv1.Obligation{},
		LatencyMs:   7,
		EvaluatedAt: "2026-08-31T12:00:00Z",
	}
}

// signed returns a signed sample decision plus the keyring that signed it.
func signed(t *testing.T) (contractsv1.Decision, *Keyring) {
	t.Helper()
	kr := NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	s, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	d := sampleDecision()
	if err := s.Sign(&d); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return d, kr
}

// pubFromJWKS extracts the active public key the way a third party would: from the
// published JWKS only, with no access to the signing internals.
func pubFromJWKS(t *testing.T, kr *Keyring, kid string) ed25519.PublicKey {
	t.Helper()
	for _, j := range kr.JWKS().Keys {
		if j.Kid == kid {
			pub, err := PublicKeyFromJWK(j)
			if err != nil {
				t.Fatalf("jwk parse: %v", err)
			}
			return pub
		}
	}
	t.Fatalf("kid %q not in JWKS", kid)
	return nil
}

func TestSignVerify_RoundTrip(t *testing.T) {
	d, kr := signed(t)

	if d.Signature.Algorithm != Algorithm || d.Signature.Canonicalization != Canonicalization {
		t.Errorf("signature metadata wrong: %+v", d.Signature)
	}
	if d.Signature.KeyID == "" || d.Signature.Value == "" {
		t.Error("missing key id or value")
	}

	// Verify independently, using only the Decision + the JWKS-published public key.
	pub := pubFromJWKS(t, kr, d.Signature.KeyID)
	if err := Verify(d, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestCanonicalMessage_Deterministic(t *testing.T) {
	d := sampleDecision()
	m1, err := CanonicalMessage(d)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	m2, _ := CanonicalMessage(d)
	if string(m1) != string(m2) {
		t.Fatalf("canonicalization not deterministic")
	}
	// JCS sorts object keys, so evidence key order in the source must not matter.
	d2 := sampleDecision()
	d2.Explanation.MatchedRules[0].Evidence = map[string]interface{}{"currency": "USD", "limit": "5000.00", "amount": "6000.00"}
	m3, _ := CanonicalMessage(d2)
	if string(m1) != string(m3) {
		t.Fatalf("evidence key order changed canonical bytes:\n%s\n%s", m1, m3)
	}
}

func TestVerify_TamperEverySignedField(t *testing.T) {
	pub := func(kr *Keyring, kid string) ed25519.PublicKey { return pubFromJWKS(t, kr, kid) }

	cases := map[string]func(*contractsv1.Decision){
		"verdict":             func(d *contractsv1.Decision) { d.Verdict = contractsv1.VerdictApprove },
		"decision_id":         func(d *contractsv1.Decision) { d.DecisionID = "01HXYZ8K3M9QF0R7S2T4V6W8XB" },
		"policy_version_hash": func(d *contractsv1.Decision) { d.PolicyVersionHash = "pol_other" },
		"summary":             func(d *contractsv1.Decision) { d.Explanation.Summary = "Approved." },
		"matched_detail":      func(d *contractsv1.Decision) { d.Explanation.MatchedRules[0].Detail = "amount=1.00 within limit" },
		"evidence_digit":      func(d *contractsv1.Decision) { d.Explanation.MatchedRules[0].Evidence["amount"] = "5000.00" },
		"evaluated_at":        func(d *contractsv1.Decision) { d.EvaluatedAt = "2020-01-01T00:00:00Z" },
		"shadow":              func(d *contractsv1.Decision) { d.Shadow = true },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d, kr := signed(t)
			p := pub(kr, d.Signature.KeyID)
			mutate(&d)
			if err := Verify(d, p); err == nil {
				t.Errorf("tampering %q still verified — signature does not cover it", name)
			}
		})
	}
}

func TestVerify_ExcludedFieldsDoNotAffectSignature(t *testing.T) {
	d, kr := signed(t)
	pub := pubFromJWKS(t, kr, d.Signature.KeyID)

	// latency_ms and the record-only fields are outside the signed set — changing
	// them must NOT break verification.
	d.LatencyMs = 999
	d.RecordHash = "chain_abc"
	verified := true
	d.SignatureVerified = &verified

	if err := Verify(d, pub); err != nil {
		t.Fatalf("excluded-field change broke verification: %v", err)
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	d, _ := signed(t)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := Verify(d, otherPub); err == nil {
		t.Error("verified under an unrelated public key")
	}
}

func TestKeyRotation_RetiringKeyStillVerifies(t *testing.T) {
	// Sign under key A, then rotate: A becomes retiring (public-only), B active.
	kr := NewKeyring()
	idA, _ := kr.GenerateActive()
	sA, _ := kr.Signer()
	d := sampleDecision()
	_ = sA.Sign(&d)
	pubA, _ := kr.PublicKey(idA)

	// New keyring after rotation: B active, A retiring (published for verification).
	rotated := NewKeyring()
	_, _ = rotated.GenerateActive()
	if err := rotated.AddRetiring(idA, pubA); err != nil {
		t.Fatalf("add retiring: %v", err)
	}
	// The old decision (signed under A) still verifies via the keyring.
	if err := rotated.VerifyDecision(d); err != nil {
		t.Fatalf("retiring key failed to verify old decision: %v", err)
	}
}

func TestVerify_UnsupportedMetadataRejected(t *testing.T) {
	d, kr := signed(t)
	pub := pubFromJWKS(t, kr, d.Signature.KeyID)

	bad := d
	bad.Signature.Algorithm = "HS256"
	if err := Verify(bad, pub); err == nil {
		t.Error("accepted non-Ed25519 algorithm")
	}
	bad = d
	bad.Signature.Canonicalization = "ti-decision-canon/2"
	if err := Verify(bad, pub); err == nil {
		t.Error("accepted unknown canonicalization")
	}
}

func TestJWKS_Shape(t *testing.T) {
	_, kr := signed(t)
	set := kr.JWKS()
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	j := set.Keys[0]
	if j.Kty != "OKP" || j.Crv != "Ed25519" || j.Use != "sig" {
		t.Errorf("jwk metadata wrong: %+v", j)
	}
	if j.Status != StatusActive {
		t.Errorf("status = %q, want active", j.Status)
	}
}

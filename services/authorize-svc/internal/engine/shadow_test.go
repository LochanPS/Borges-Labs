package engine

import (
	"context"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/signing"
)

// The shadow flag is honored and, crucially, is part of the SIGNED bytes: a decision
// signed as shadow=true verifies as shadow=true (and false as false), so a caller
// cannot strip the advisory marker without breaking the signature (A#5).
func TestAuthorize_ShadowFlagIsSigned(t *testing.T) {
	kr := signing.NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pub, _ := kr.PublicKey(signer.KeyID())
	e := NewEngine(fixturePolicy(), signer.KeyID()).WithSigner(signer)

	for _, shadow := range []bool{true, false} {
		d, err := e.Authorize(context.Background(), "", baseReq(), shadow)
		if err != nil {
			t.Fatalf("authorize(shadow=%v): %v", shadow, err)
		}
		if d.Shadow != shadow {
			t.Errorf("decision shadow = %v, want %v", d.Shadow, shadow)
		}
		if err := signing.Verify(d, pub); err != nil {
			t.Errorf("signature verify (shadow=%v): %v", shadow, err)
		}
	}
}

// Evaluate is pure: identical (policy, request, evaluated_at) yields identical verdict
// and explanation, and it attaches no signature/shadow (Authorize adds those).
func TestEvaluate_PureAndUnsigned(t *testing.T) {
	pol := fixturePolicy()
	a := Evaluate(pol, baseReq(), monNoon)
	b := Evaluate(pol, baseReq(), monNoon)
	if a.Verdict != b.Verdict || a.Explanation.Summary != b.Explanation.Summary {
		t.Error("Evaluate is not deterministic")
	}
	if a.Signature.Value != "" || a.Shadow {
		t.Errorf("Evaluate attached signature/shadow: sig=%q shadow=%v", a.Signature.Value, a.Shadow)
	}
	if a.PolicyVersionHash != pol.Version {
		t.Errorf("cited %q, want %q", a.PolicyVersionHash, pol.Version)
	}
}

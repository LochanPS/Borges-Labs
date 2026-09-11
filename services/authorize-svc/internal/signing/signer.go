package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// ErrInvalidSignature is returned when a decision's signature does not verify.
var ErrInvalidSignature = errors.New("signing: signature verification failed")

// b64 is base64url without padding — the encoding used for signature values and JWK
// key material (RFC 7515/7518).
var b64 = base64.RawURLEncoding

// Signer produces Ed25519 signatures over decisions under a single key id.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// KeyID returns the id this signer stamps on signatures.
func (s *Signer) KeyID() string { return s.keyID }

// Sign canonicalizes the decision and writes its Ed25519 signature into
// d.Signature. The signature covers only the allowlisted fields (canon doc §1), so
// server-only fields (latency_ms, record_hash, …) can change without invalidating it.
func (s *Signer) Sign(d *contractsv1.Decision) error {
	msg, err := CanonicalMessage(*d)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(s.priv, msg)
	d.Signature = contractsv1.Signature{
		Algorithm:        Algorithm,
		KeyID:            s.keyID,
		Value:            b64.EncodeToString(sig),
		Canonicalization: Canonicalization,
	}
	return nil
}

// SignDetached signs an already-canonical message under the active key and returns
// the Signature envelope. Unlike Sign, it is not tied to the Decision shape: an
// artifact that defines its own canonicalization (e.g. a published policy version —
// Task 2.1) passes its canonical bytes and canonicalization id here. The same
// Ed25519 key that signs decisions signs policy versions, so both verify against the
// public key published at GET /v1/keys/public.
func (s *Signer) SignDetached(canonicalization string, msg []byte) contractsv1.Signature {
	sig := ed25519.Sign(s.priv, msg)
	return contractsv1.Signature{
		Algorithm:        Algorithm,
		KeyID:            s.keyID,
		Value:            b64.EncodeToString(sig),
		Canonicalization: canonicalization,
	}
}

// VerifyDetached checks a detached signature (from SignDetached) over msg against
// pub. It is the standalone counterpart to SignDetached: a third party verifies a
// policy version with just the canonical bytes, the signature, and the public key.
// The caller is responsible for reproducing msg from the artifact's documented
// canonicalization and for confirming sig.Canonicalization is the scheme it expects.
func VerifyDetached(pub ed25519.PublicKey, msg []byte, sig contractsv1.Signature) error {
	if sig.Algorithm != Algorithm {
		return fmt.Errorf("signing: unsupported algorithm %q", sig.Algorithm)
	}
	raw, err := b64.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("signing: decode signature value: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signing: bad public key size %d", len(pub))
	}
	if !ed25519.Verify(pub, msg, raw) {
		return ErrInvalidSignature
	}
	return nil
}

// Verify checks a decision's signature against the given public key. It is a
// standalone function: it needs nothing from the signing service, so a third party
// can verify with just the Decision and the published public key.
func Verify(d contractsv1.Decision, pub ed25519.PublicKey) error {
	if d.Signature.Algorithm != Algorithm {
		return fmt.Errorf("signing: unsupported algorithm %q", d.Signature.Algorithm)
	}
	if d.Signature.Canonicalization != Canonicalization {
		return fmt.Errorf("signing: unsupported canonicalization %q", d.Signature.Canonicalization)
	}
	sig, err := b64.DecodeString(d.Signature.Value)
	if err != nil {
		return fmt.Errorf("signing: decode signature value: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signing: bad public key size %d", len(pub))
	}
	msg, err := CanonicalMessage(d)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

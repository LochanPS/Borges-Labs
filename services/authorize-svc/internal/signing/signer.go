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

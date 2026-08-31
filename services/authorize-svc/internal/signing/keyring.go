package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Key status values published in the JWKS so verifiers know which keys are current.
const (
	StatusActive   = "active"   // the key new decisions are signed under
	StatusRetiring = "retiring" // rotated out; kept published until old decisions age out
)

// keyEntry is one key in the ring. The private half is present only for keys this
// process can sign with (in MVP, just the active key).
type keyEntry struct {
	id     string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey // nil for verify/publish-only keys
	status string
}

// Keyring holds the signing keys: one active signer plus any retiring keys still
// published for verification. Never reuse a key id (canon doc §4).
type Keyring struct {
	active string
	keys   map[string]keyEntry
}

// NewKeyring builds an empty keyring.
func NewKeyring() *Keyring { return &Keyring{keys: make(map[string]keyEntry)} }

// SetActive installs the active signing key from a 32-byte Ed25519 seed.
func (k *Keyring) SetActive(id string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("signing: seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	k.keys[id] = keyEntry{
		id:     id,
		pub:    priv.Public().(ed25519.PublicKey),
		priv:   priv,
		status: StatusActive,
	}
	k.active = id
	return nil
}

// AddRetiring publishes a public-only key that decisions were previously signed
// under, so those older receipts keep verifying after rotation.
func (k *Keyring) AddRetiring(id string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("signing: public key must be %d bytes", ed25519.PublicKeySize)
	}
	if _, exists := k.keys[id]; exists {
		return fmt.Errorf("signing: key id %q already present", id)
	}
	k.keys[id] = keyEntry{id: id, pub: pub, status: StatusRetiring}
	return nil
}

// GenerateActive creates a fresh Ed25519 key, installs it as active, and returns its
// id. For local/dev use where no key is provisioned; production supplies a seed from
// the secret manager / KMS.
func (k *Keyring) GenerateActive() (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("signing: generate key: %w", err)
	}
	id := deriveKeyID(pub)
	k.keys[id] = keyEntry{id: id, pub: pub, priv: priv, status: StatusActive}
	k.active = id
	return id, nil
}

// Signer returns a Signer for the active key, or an error if none is set.
func (k *Keyring) Signer() (*Signer, error) {
	e, ok := k.keys[k.active]
	if !ok || e.priv == nil {
		return nil, errors.New("signing: no active signing key")
	}
	return &Signer{keyID: e.id, priv: e.priv}, nil
}

// PublicKey returns the public key for a key id (active or retiring).
func (k *Keyring) PublicKey(id string) (ed25519.PublicKey, bool) {
	e, ok := k.keys[id]
	if !ok {
		return nil, false
	}
	return e.pub, true
}

// VerifyDecision verifies a decision against the public key named by its signature's
// key id — the service-side counterpart to the standalone Verify.
func (k *Keyring) VerifyDecision(d contractsv1.Decision) error {
	pub, ok := k.PublicKey(d.Signature.KeyID)
	if !ok {
		return fmt.Errorf("signing: unknown key id %q", d.Signature.KeyID)
	}
	return Verify(d, pub)
}

// JWK is a JSON Web Key for an Ed25519 public key (RFC 8037 OKP). The field set
// matches the frozen contract (getPublicKeys): kty, crv, kid, x, use, status.
type JWK struct {
	Kty    string `json:"kty"`    // "OKP"
	Crv    string `json:"crv"`    // "Ed25519"
	Kid    string `json:"kid"`    // key id
	X      string `json:"x"`      // base64url public key
	Use    string `json:"use"`    // "sig"
	Status string `json:"status"` // active | retiring
}

// JWKS is the JSON Web Key Set served at GET /v1/keys/public.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS renders every published key (active first, then retiring) as a JWK set. The
// order is stable so the endpoint's output is deterministic.
func (k *Keyring) JWKS() JWKS {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ai, aj := k.keys[ids[i]], k.keys[ids[j]]
		if (ai.status == StatusActive) != (aj.status == StatusActive) {
			return ai.status == StatusActive // active keys first
		}
		return ids[i] < ids[j]
	})

	out := JWKS{Keys: make([]JWK, 0, len(ids))}
	for _, id := range ids {
		e := k.keys[id]
		out.Keys = append(out.Keys, JWK{
			Kty:    "OKP",
			Crv:    "Ed25519",
			Kid:    e.id,
			X:      b64.EncodeToString(e.pub),
			Use:    "sig",
			Status: e.status,
		})
	}
	return out
}

// deriveKeyID makes a stable, non-secret id from a public key: a short prefix of its
// SHA-256. Used for generated dev keys; production names keys explicitly.
func deriveKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "azn-sign-" + b64.EncodeToString(sum[:])[:12]
}

// PublicKeyFromJWK parses an Ed25519 public key out of a JWK (for a standalone
// verifier that fetched the JWKS).
func PublicKeyFromJWK(j JWK) (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("signing: not an Ed25519 OKP key (kty=%q crv=%q)", j.Kty, j.Crv)
	}
	raw, err := b64.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("signing: decode jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing: jwk x is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

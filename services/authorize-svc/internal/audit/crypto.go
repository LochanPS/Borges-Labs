package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Encryptor provides field-level encryption for the sensitive audit fields
// (amount/target — A#10). It is a seam so the store can be configured with real
// AES-GCM in production or a no-op in dev/CI without a key.
//
// The contract with the store: Decrypt(Encrypt(x)) == x, and Decrypt must accept a
// value that was stored WITHOUT encryption (a plaintext passthrough), so a service
// that gains or loses a key can still read older rows. Ciphertext is self-marking
// via a version prefix; anything without the prefix is treated as stored plaintext.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(stored string) (string, error)
}

// cipherPrefix marks an AES-GCM ciphertext. A stored value lacking it is plaintext.
const cipherPrefix = "enc:v1:"

// NopEncryptor stores fields as plaintext. Used in dev/CI when no key is configured.
// Decrypt still strips a cipher prefix if present is NOT possible without a key, so
// a Nop encryptor only ever produced plaintext and only reads plaintext back.
type NopEncryptor struct{}

func (NopEncryptor) Encrypt(plaintext string) (string, error) { return plaintext, nil }

// Decrypt returns stored as-is when it is plaintext. If it carries the cipher prefix
// (encrypted by a previously-configured key that is now absent), it errors rather
// than returning ciphertext as if it were the value.
func (NopEncryptor) Decrypt(stored string) (string, error) {
	if strings.HasPrefix(stored, cipherPrefix) {
		return "", fmt.Errorf("audit: value is encrypted but no encryption key is configured")
	}
	return stored, nil
}

// AESGCM encrypts fields with AES-256-GCM under a single 32-byte key. Each Encrypt
// uses a fresh random nonce; the stored form is cipherPrefix + base64(nonce‖ct).
type AESGCM struct {
	aead cipher.AEAD
}

// NewAESGCM builds an AES-256-GCM encryptor from a 32-byte key.
func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("audit: encryption key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("audit: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("audit: new gcm: %w", err)
	}
	return &AESGCM{aead: aead}, nil
}

// Encrypt seals plaintext under a fresh nonce and returns the marked base64 form.
func (e *AESGCM) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("audit: nonce: %w", err)
	}
	sealed := e.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return cipherPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. A value without the cipher prefix is returned as-is
// (stored plaintext), so rows written before a key was configured still read.
func (e *AESGCM) Decrypt(stored string) (string, error) {
	if !strings.HasPrefix(stored, cipherPrefix) {
		return stored, nil // stored plaintext (no key at write time)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, cipherPrefix))
	if err != nil {
		return "", fmt.Errorf("audit: decode ciphertext: %w", err)
	}
	ns := e.aead.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("audit: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := e.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("audit: decrypt: %w", err)
	}
	return string(pt), nil
}

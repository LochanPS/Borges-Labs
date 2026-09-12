// Package auth implements request authentication for the decision plane (TRD §11).
//
// Three concerns, kept distinct:
//
//   - API keys — a 256-bit crypto-random secret, formatted azn_live_<...> /
//     azn_test_<...>. The server stores ONLY sha256(key); it never persists the raw
//     key. A presented key is identified by a PUBLIC key id (prefix + a hash prefix)
//     and verified by a constant-time compare of sha256(presented) against the
//     stored hash (crypto/subtle). A Redis cache of key_id -> record (5-min TTL)
//     fronts Postgres (the source of truth).
//
//   - HMAC request signing (caller -> us) — the caller signs a canonical payload
//     (method, path, timestamp, nonce, body hash) with the API key as the HMAC
//     secret and sends the MAC in X-Signature. The server recomputes the MAC using
//     the key presented on THIS request (available transiently from the
//     Authorization header, over TLS — never stored) and compares constant-time.
//     Requests whose timestamp is outside the configured skew are rejected. This is
//     SYMMETRIC HMAC and is entirely separate from the ASYMMETRIC Ed25519 signature
//     the service puts on a Decision (ROADMAP A#1).
//
//   - Replay protection — a per-key nonce cache in Redis with a short TTL. A nonce
//     is remembered only after the signature verifies, so an attacker cannot burn
//     nonces without a valid signature. A reused (key_id, nonce) pair is rejected.
//
// Security invariants for this file:
//   - Never log a raw key, a signature, or an HMAC. Log the public key id / org id.
//   - Every secret comparison is constant-time (crypto/subtle, crypto/hmac).
//   - On a backing-store failure the authenticator FAILS CLOSED (rejects), never
//     open — a replay check we cannot perform is a replay check that failed.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Key environment tags. A key is either live or test; the two never mix.
const (
	EnvLive = "live"
	EnvTest = "test"
)

// Key status values. A revoked key authenticates (the credential is valid) but is
// refused with 403 — the distinction the caller needs to tell "wrong key" from
// "your key was turned off".
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// Prefixes for the two environments. The prefix is part of the signed/hashed key
// material, so a live key can never be presented as a test key or vice versa.
const (
	prefixLive = "azn_live_"
	prefixTest = "azn_test_"
)

// canonScheme is the versioned label that leads every canonical signing string, so
// the signature scheme can evolve without ambiguity. Documented in
// docs/request-authentication.md.
const canonScheme = "azn-hmac/1"

// secretBytes is the entropy in a generated key (256 bits, TRD §11).
const secretBytes = 32

// keyIDHashPrefixLen is how many hex characters of sha256(key) go into the public
// key id. Long enough to be collision-free for lookup, short enough to stay opaque.
const keyIDHashPrefixLen = 16

// b32 encodes key secrets: lowercase Crockford-free RFC 4648 base32 without padding.
// Base32 keeps keys copy-paste safe (no case-fold or URL-escaping surprises).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// KeyRecord is the stored, non-secret description of an API key. It holds sha256 of
// the key, never the key itself.
type KeyRecord struct {
	KeyID      string // public id (prefix + hash prefix); safe to log/index
	KeyHashHex string // hex sha256(rawKey); the only stored form of the secret
	OrgID      string
	Tier       string // drives rate limits (Task 1.3) and quotas
	Env        string // EnvLive | EnvTest
	Status     string // StatusActive | StatusRevoked
	// Shadow marks a log-only (advisory) key: decisions are evaluated and audited but
	// flagged shadow so the caller does NOT enforce them (ROADMAP Task 2.3, A#5
	// advisory-first). New keys default to shadow=true; flipping a key to enforce is
	// shadow=false — the go/no-go lever for one agent at a time (ROADMAP §6.1).
	Shadow bool
}

// Principal is the authenticated caller handed to downstream handlers.
type Principal struct {
	OrgID  string
	KeyID  string
	Tier   string
	Env    string
	Shadow bool
}

// Error is an authentication failure with the HTTP status and machine code the HTTP
// layer should surface. Detail is caller-safe (never contains secret material).
type Error struct {
	Status int
	Code   string
	Title  string
	Detail string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// Machine-readable auth error codes (mirrored in the server's problem codes).
const (
	CodeUnauthorized   = "unauthorized"
	CodeForbidden      = "forbidden"
	CodeReplayDetected = "replay_detected"
	CodeUnavailable    = "auth_unavailable"
)

// Pre-built errors for the common cases. Details are deliberately vague on the
// 401s so a caller cannot distinguish "no such key" from "bad signature" (no
// oracle). Fresh values are allocated where a specific detail helps the developer.
func errUnauthorized(detail string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: CodeUnauthorized, Title: "Unauthorized", Detail: detail}
}

func errForbidden(detail string) *Error {
	return &Error{Status: http.StatusForbidden, Code: CodeForbidden, Title: "Forbidden", Detail: detail}
}

func errReplay() *Error {
	return &Error{Status: http.StatusUnauthorized, Code: CodeReplayDetected, Title: "Unauthorized", Detail: "Request nonce has already been used."}
}

func errUnavailable() *Error {
	return &Error{Status: http.StatusServiceUnavailable, Code: CodeUnavailable, Title: "Authentication unavailable", Detail: "Could not verify the request. Please retry."}
}

// ErrKeyNotFound is returned by a KeyStore when no record matches the key id.
var ErrKeyNotFound = errors.New("auth: key not found")

// KeyStore resolves a public key id to its record. Implementations: Postgres (source
// of truth), a Redis-cached wrapper, and an in-memory fake for tests.
type KeyStore interface {
	LookupByID(ctx context.Context, keyID string) (KeyRecord, error)
}

// NonceStore remembers per-key nonces for replay protection. Remember atomically
// records (keyID, nonce) and reports whether it was fresh (not seen before).
type NonceStore interface {
	Remember(ctx context.Context, keyID, nonce string, ttl time.Duration) (fresh bool, err error)
}

// Authenticator verifies API key + HMAC signature + nonce on a request.
type Authenticator struct {
	keys     KeyStore
	nonces   NonceStore
	maxSkew  time.Duration
	nonceTTL time.Duration
	now      func() time.Time
}

// Config parameterizes an Authenticator.
type Config struct {
	// MaxSkew is the largest allowed difference between the request timestamp and
	// server time, in either direction. Bounds the replay window.
	MaxSkew time.Duration
	// NonceTTL is how long a nonce is remembered. Must be >= 2*MaxSkew so a nonce is
	// still remembered for any timestamp that could still pass the skew check.
	NonceTTL time.Duration
}

// New builds an Authenticator. A nil-safe clock is installed if none is given.
func New(keys KeyStore, nonces NonceStore, cfg Config) *Authenticator {
	if cfg.NonceTTL < 2*cfg.MaxSkew {
		// Guard the invariant that makes replay protection sound.
		cfg.NonceTTL = 2 * cfg.MaxSkew
	}
	return &Authenticator{
		keys:     keys,
		nonces:   nonces,
		maxSkew:  cfg.MaxSkew,
		nonceTTL: cfg.NonceTTL,
		now:      time.Now,
	}
}

// Authenticate verifies the request and returns the caller principal, or an *Error
// carrying the status/code the HTTP layer must surface.
//
// body is the exact request body bytes (already length-limited by the caller); it is
// hashed into the canonical signing string, so a tampered body fails verification.
func (a *Authenticator) Authenticate(ctx context.Context, method, path string, header http.Header, body []byte) (Principal, *Error) {
	rawKey, aerr := bearerKey(header)
	if aerr != nil {
		return Principal{}, aerr
	}

	keyID, keyHashHex, aerr := parseKey(rawKey)
	if aerr != nil {
		return Principal{}, aerr
	}

	rec, err := a.keys.LookupByID(ctx, keyID)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return Principal{}, errUnauthorized("Invalid API key.")
		}
		return Principal{}, errUnavailable() // fail closed on store error
	}

	// Constant-time verify the presented key against the stored hash. A mismatch is
	// indistinguishable (to timing and to the caller) from "no such key".
	storedHash, err := hex.DecodeString(rec.KeyHashHex)
	if err != nil {
		return Principal{}, errUnavailable()
	}
	presentedHash, err := hex.DecodeString(keyHashHex)
	if err != nil {
		return Principal{}, errUnauthorized("Invalid API key.")
	}
	if subtle.ConstantTimeCompare(storedHash, presentedHash) != 1 {
		return Principal{}, errUnauthorized("Invalid API key.")
	}

	// Valid credential — a revoked key is now a 403, not a 401.
	if rec.Status == StatusRevoked {
		return Principal{}, errForbidden("This API key has been revoked.")
	}
	if rec.Status != StatusActive {
		return Principal{}, errForbidden("This API key is not active.")
	}

	// HMAC request signature over the canonical payload.
	if aerr := a.verifySignature(method, path, header, body, rawKey); aerr != nil {
		return Principal{}, aerr
	}

	// Replay check LAST: only a validly signed request may consume a nonce.
	nonce := header.Get("X-Nonce")
	fresh, err := a.nonces.Remember(ctx, rec.KeyID, nonce, a.nonceTTL)
	if err != nil {
		return Principal{}, errUnavailable() // fail closed: cannot prove non-replay
	}
	if !fresh {
		return Principal{}, errReplay()
	}

	return Principal{OrgID: rec.OrgID, KeyID: rec.KeyID, Tier: rec.Tier, Env: rec.Env, Shadow: rec.Shadow}, nil
}

// verifySignature checks the timestamp skew and the HMAC over the canonical payload.
func (a *Authenticator) verifySignature(method, path string, header http.Header, body []byte, rawKey string) *Error {
	tsRaw := header.Get("X-Timestamp")
	nonce := header.Get("X-Nonce")
	sigHex := header.Get("X-Signature")
	if tsRaw == "" || nonce == "" || sigHex == "" {
		return errUnauthorized("Missing X-Timestamp, X-Nonce, or X-Signature header.")
	}
	if l := len(nonce); l < 8 || l > 128 {
		return errUnauthorized("X-Nonce must be 8..128 characters.")
	}

	tsSecs, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return errUnauthorized("X-Timestamp must be Unix seconds.")
	}
	skew := a.now().UTC().Sub(time.Unix(tsSecs, 0).UTC())
	if skew < 0 {
		skew = -skew
	}
	if skew > a.maxSkew {
		return errUnauthorized("Request timestamp is outside the allowed skew window.")
	}

	presentedMAC, err := hex.DecodeString(sigHex)
	if err != nil {
		return errUnauthorized("X-Signature must be lowercase hex.")
	}

	expectedMAC := computeMAC(rawKey, canonicalString(method, path, tsRaw, nonce, body))
	if !hmac.Equal(expectedMAC, presentedMAC) {
		return errUnauthorized("Request signature is invalid.")
	}
	return nil
}

// canonicalString builds the exact bytes both sides sign. The format is versioned
// and newline-delimited; the body is represented by its sha256 so the payload stays
// small and binary-safe. Documented in docs/request-authentication.md — any change
// here is a breaking protocol change and must bump canonScheme.
func canonicalString(method, path, timestamp, nonce string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	var b strings.Builder
	b.WriteString(canonScheme)
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(path)
	b.WriteByte('\n')
	b.WriteString(timestamp)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(hex.EncodeToString(bodyHash[:]))
	return []byte(b.String())
}

// computeMAC returns HMAC-SHA256(rawKey, msg). The API key is the shared secret.
func computeMAC(rawKey string, msg []byte) []byte {
	mac := hmac.New(sha256.New, []byte(rawKey))
	mac.Write(msg)
	return mac.Sum(nil)
}

// Sign is the client-side counterpart to verifySignature: it produces the hex MAC a
// caller puts in X-Signature. Exported so the SDKs and tests sign identically.
func Sign(rawKey, method, path, timestamp, nonce string, body []byte) string {
	return hex.EncodeToString(computeMAC(rawKey, canonicalString(method, path, timestamp, nonce, body)))
}

// bearerKey extracts the API key from the Authorization header ("Bearer <key>") or,
// as a convenience, from X-Api-Key. It never returns partial/echoed key material in
// an error.
func bearerKey(header http.Header) (string, *Error) {
	if authz := header.Get("Authorization"); authz != "" {
		const bearer = "Bearer "
		if len(authz) > len(bearer) && strings.EqualFold(authz[:len(bearer)], bearer) {
			return strings.TrimSpace(authz[len(bearer):]), nil
		}
		return "", errUnauthorized("Authorization header must be 'Bearer <api_key>'.")
	}
	if k := header.Get("X-Api-Key"); k != "" {
		return strings.TrimSpace(k), nil
	}
	return "", errUnauthorized("Missing API key.")
}

// parseKey validates the key format and derives its public key id and stored hash.
// It does not touch any store, so a malformed key is rejected before I/O.
func parseKey(rawKey string) (keyID, keyHashHex string, aerr *Error) {
	if !strings.HasPrefix(rawKey, prefixLive) && !strings.HasPrefix(rawKey, prefixTest) {
		return "", "", errUnauthorized("Invalid API key.")
	}
	sum := sha256.Sum256([]byte(rawKey))
	hashHex := hex.EncodeToString(sum[:])
	return KeyID(rawKey, hashHex), hashHex, nil
}

// KeyID derives the public, non-secret identifier for a key: its environment prefix
// plus a prefix of sha256(key). Deterministic, so the client and server agree, and
// safe to log or index.
func KeyID(rawKey, hashHex string) string {
	prefix := prefixLive
	if strings.HasPrefix(rawKey, prefixTest) {
		prefix = prefixTest
	}
	return prefix + hashHex[:keyIDHashPrefixLen]
}

// --- key generation ---------------------------------------------------------

// GeneratedKey is the output of NewKey: the plaintext key (shown to the caller
// exactly once) and its stored record (which holds only the hash).
type GeneratedKey struct {
	Plaintext string
	Record    KeyRecord
}

// NewKey mints a fresh 256-bit API key for the given environment, org, and tier.
// The plaintext is returned once; only Record (with sha256) should be persisted.
func NewKey(env, orgID, tier string) (GeneratedKey, error) {
	prefix := prefixLive
	if env == EnvTest {
		prefix = prefixTest
	} else if env != EnvLive {
		return GeneratedKey{}, fmt.Errorf("auth: unknown env %q", env)
	}

	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return GeneratedKey{}, fmt.Errorf("auth: read entropy: %w", err)
	}
	rawKey := prefix + strings.ToLower(b32.EncodeToString(buf))

	sum := sha256.Sum256([]byte(rawKey))
	hashHex := hex.EncodeToString(sum[:])

	return GeneratedKey{
		Plaintext: rawKey,
		Record: KeyRecord{
			KeyID:      KeyID(rawKey, hashHex),
			KeyHashHex: hashHex,
			OrgID:      orgID,
			Tier:       tier,
			Env:        env,
			Status:     StatusActive,
			// Advisory-first (A#5): a freshly minted key runs in shadow until it is
			// deliberately flipped to enforce.
			Shadow: true,
		},
	}, nil
}

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/idempotency"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

const testTier = "default"

// authHarness is a running service seeded with one active and one revoked test key
// (the fixture the acceptance criteria call for), plus helpers to sign requests the
// way a real client would. It wires a REAL Ed25519 signer and an in-memory audit
// store so the /v1/decisions endpoints can be exercised end to end.
type authHarness struct {
	ts      *httptest.Server
	active  string // plaintext active key
	revoked string // plaintext revoked key
	orgID   string // org the active/revoked keys belong to
	store   *audit.MemStore
	writer  *audit.Writer
	idem    *idempotency.Mem
}

func okPing(context.Context) error { return nil }

// stubAuthz is the default authorizer factory: the hardcoded-APPROVE engine stub,
// really signed. Used by every existing test that only cares about the HTTP surface.
func stubAuthz(signer *signing.Signer) Authorizer {
	return engine.Stub{
		PolicyVersionHash: "pol_test_0000000000000000000000000000000000000000000000000000000000000000",
		SigningKeyID:      signer.KeyID(),
		Signer:            signer,
	}
}

// newAuthHarness builds a harness with effectively-unlimited rate limits (rate
// limiting is exercised separately in ratelimit_test.go, so functional tests that
// fire many requests are not throttled).
func newAuthHarness(t *testing.T) *authHarness {
	generous := ratelimit.TierTable{"default": {PerMinute: 1_000_000, PerSecond: 1_000_000}}
	return newAuthHarnessWith(t, testLimiter(), generous)
}

// newAuthHarnessWith lets a test inject a specific limiter and tier table (used by
// the rate-limit acceptance test). It uses the stub authorizer.
func newAuthHarnessWith(t *testing.T, limiter ratelimit.Limiter, tiers ratelimit.TierTable) *authHarness {
	return newAuthHarnessFull(t, limiter, tiers, stubAuthz)
}

// newAuthHarnessFull is the full builder: it wires a real Ed25519 signer, an
// in-memory audit store, and an in-memory idempotency cache, and lets the caller
// choose the authorizer (stub or the real engine over a policy fixture).
func newAuthHarnessFull(t *testing.T, limiter ratelimit.Limiter, tiers ratelimit.TierTable, authzFor func(*signing.Signer) Authorizer) *authHarness {
	t.Helper()

	activeGK, err := auth.NewKey(auth.EnvTest, "org_test", testTier)
	if err != nil {
		t.Fatalf("gen active key: %v", err)
	}
	revokedGK, err := auth.NewKey(auth.EnvTest, "org_test", testTier)
	if err != nil {
		t.Fatalf("gen revoked key: %v", err)
	}
	revRec := revokedGK.Record
	revRec.Status = auth.StatusRevoked

	keys := auth.NewMemKeyStore(activeGK.Record, revRec)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	// Real Ed25519 signer, shared with the read-path verifier so signature_verified
	// is meaningful. Field-level encryption on, to exercise the at-rest path.
	keyring := signing.NewKeyring()
	if _, err := keyring.GenerateActive(); err != nil {
		t.Fatalf("gen signing key: %v", err)
	}
	signer, err := keyring.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	authz := authzFor(signer)

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("enc key: %v", err)
	}
	enc, err := audit.NewAESGCM(encKey)
	if err != nil {
		t.Fatalf("aesgcm: %v", err)
	}
	store := audit.NewMemStore(enc)
	writer := audit.NewWriter(store, log, 64)
	writer.Start()
	t.Cleanup(func() { _ = writer.Close(context.Background()) })

	retentionFor := func(tier string) time.Duration { return 90 * 24 * time.Hour }

	idem := idempotency.NewMem()

	srv := New(log, BuildInfo{Version: "test", Commit: "abc", Date: "now"},
		authz, testAuthn(keys), limiter, tiers,
		Check{Name: "postgres", Ping: okPing},
		Check{Name: "redis", Ping: okPing},
	).WithKeys(func() any { return keyring.JWKS() }).
		WithAudit(writer, store, keyring.VerifyDecision, retentionFor).
		WithIdempotency(idem)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &authHarness{
		ts: ts, active: activeGK.Plaintext, revoked: revokedGK.Plaintext,
		orgID: "org_test", store: store, writer: writer, idem: idem,
	}
}

func newNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("nonce entropy: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// signedRequest builds a fully signed request (fresh timestamp + nonce).
func (h *authHarness) signedRequest(t *testing.T, method, path string, body []byte, key string) *http.Request {
	t.Helper()
	return h.signedRequestAt(t, method, path, body, key, time.Now().Unix(), newNonce(t))
}

// signedRequestAt builds a signed request with an explicit timestamp and nonce, so a
// test can force skew or a nonce reuse.
func (h *authHarness) signedRequestAt(t *testing.T, method, path string, body []byte, key string, tsUnix int64, nonce string) *http.Request {
	t.Helper()
	tsStr := strconv.FormatInt(tsUnix, 10)
	req, err := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Timestamp", tsStr)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", auth.Sign(key, method, path, tsStr, nonce, body))
	return req
}

func do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// --- acceptance: valid signed request passes ---------------------------------

func TestAuth_ValidSignedRequestPasses(t *testing.T) {
	h := newAuthHarness(t)
	decisionSchema := compileContract(t, decisionSchemaID)

	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active)
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", resp.StatusCode, body)
	}
	validateAgainst(t, decisionSchema, body)

	var dec contractsv1.Decision
	if err := json.Unmarshal(body, &dec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Verdict != contractsv1.VerdictApprove {
		t.Errorf("verdict = %q, want APPROVE", dec.Verdict)
	}
}

// --- acceptance: wrong signature -> 401 --------------------------------------

func TestAuth_WrongSignatureRejected(t *testing.T) {
	h := newAuthHarness(t)
	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active)
	// Corrupt the signature after it was computed.
	req.Header.Set("X-Signature", "deadbeef")
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", resp.StatusCode, body)
	}
	assertProblemCode(t, body, auth.CodeUnauthorized)
}

// A body tampered after signing must fail (the signature covers the body hash).
func TestAuth_TamperedBodyRejected(t *testing.T) {
	h := newAuthHarness(t)
	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active)
	// Swap the body for a different (still valid) one without re-signing.
	tampered := []byte(`{"agent_id":"evil","action":"payment.create","amount":"999999.00","currency":"USD","target":{"type":"vendor","id":"x"},"idempotency_key":"idem_tampered_1"}`)
	req.Body = io.NopCloser(bytes.NewReader(tampered))
	req.ContentLength = int64(len(tampered))
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", resp.StatusCode, body)
	}
}

// --- acceptance: replayed nonce -> rejected ----------------------------------

func TestAuth_ReplayedNonceRejected(t *testing.T) {
	h := newAuthHarness(t)
	ts := time.Now().Unix()
	nonce := newNonce(t)

	// First use: accepted.
	req1 := h.signedRequestAt(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active, ts, nonce)
	resp1, body1 := do(t, req1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200; body: %s", resp1.StatusCode, body1)
	}

	// Replay with the identical timestamp + nonce + signature: rejected.
	req2 := h.signedRequestAt(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active, ts, nonce)
	resp2, body2 := do(t, req2)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401; body: %s", resp2.StatusCode, body2)
	}
	assertProblemCode(t, body2, auth.CodeReplayDetected)
}

// --- acceptance: skewed timestamp -> rejected --------------------------------

func TestAuth_SkewedTimestampRejected(t *testing.T) {
	h := newAuthHarness(t)
	// One hour in the past — well outside the 5-minute test skew.
	old := time.Now().Add(-1 * time.Hour).Unix()
	req := h.signedRequestAt(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active, old, newNonce(t))
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", resp.StatusCode, body)
	}
	assertProblemCode(t, body, auth.CodeUnauthorized)
}

// --- acceptance: revoked key -> 403 ------------------------------------------

func TestAuth_RevokedKeyForbidden(t *testing.T) {
	h := newAuthHarness(t)
	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.revoked)
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", resp.StatusCode, body)
	}
	assertProblemCode(t, body, auth.CodeForbidden)
}

// --- missing / malformed credentials -> 401 ----------------------------------

func TestAuth_MissingKeyRejected(t *testing.T) {
	h := newAuthHarness(t)
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/authorize", bytes.NewReader(validAuthorizeBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Error("missing WWW-Authenticate header on 401")
	}
}

func TestAuth_UnknownKeyRejected(t *testing.T) {
	h := newAuthHarness(t)
	// Well-formed but never-seeded key.
	unknown, err := auth.NewKey(auth.EnvTest, "org_other", testTier)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, unknown.Plaintext)
	resp, body := do(t, req)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", resp.StatusCode, body)
	}
}

// assertProblemCode checks the RFC 7807 body carries the expected machine code.
func assertProblemCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var p contractsv1.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v; body: %s", err, body)
	}
	if p.Code != want {
		t.Errorf("problem code = %q, want %q", p.Code, want)
	}
}

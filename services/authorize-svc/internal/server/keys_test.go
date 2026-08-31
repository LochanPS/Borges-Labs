package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// newSignedHarness builds a running service whose decisions are really Ed25519-signed
// and whose public keys are published at /v1/keys/public. Returns the harness (for
// signing requests), the plaintext active API key, and the keyring.
func newSignedHarness(t *testing.T) (*authHarness, *signing.Keyring) {
	t.Helper()

	kr := signing.NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	apiKey, err := auth.NewKey(auth.EnvTest, "org_test", testTier)
	if err != nil {
		t.Fatalf("gen api key: %v", err)
	}
	keys := auth.NewMemKeyStore(apiKey.Record)

	authorizer := engine.Stub{
		PolicyVersionHash: "pol_test_0000000000000000000000000000000000000000000000000000000000000000",
		SigningKeyID:      signer.KeyID(),
		Signer:            signer,
	}

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := New(log, BuildInfo{Version: "test"}, authorizer, testAuthn(keys), testLimiter(), nil,
		Check{Name: "postgres", Ping: okPing},
	).WithKeys(func() any { return kr.JWKS() })
	// nil tiers -> Resolve falls back to a safe built-in default; fine for these tests.

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &authHarness{ts: ts, active: apiKey.Plaintext}, kr
}

func TestKeysPublic_ServesJWKS(t *testing.T) {
	h, kr := newSignedHarness(t)

	resp, err := http.Get(h.ts.URL + "/v1/keys/public")
	if err != nil {
		t.Fatalf("GET keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var set signing.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	// The published key matches the keyring's active key.
	active := kr.JWKS().Keys[0]
	if set.Keys[0].Kid != active.Kid || set.Keys[0].X != active.X {
		t.Errorf("published key does not match keyring")
	}
	if _, err := signing.PublicKeyFromJWK(set.Keys[0]); err != nil {
		t.Errorf("published key is not a usable Ed25519 key: %v", err)
	}
}

func TestKeysPublic_DisabledWhenUnset(t *testing.T) {
	// A server built without WithKeys reports 503 on the endpoint.
	srv := testServer(Check{Name: "redis", Ping: okPing})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/keys/public")
	if err != nil {
		t.Fatalf("GET keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

// TestAuthorize_DecisionIsVerifiableEndToEnd is the Task 1.5 acceptance at the HTTP
// layer: a decision returned by the service verifies against the published public
// key, and tampering with it fails.
func TestAuthorize_DecisionIsVerifiableEndToEnd(t *testing.T) {
	h, _ := newSignedHarness(t)

	// Get a real, signed decision.
	req := h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active)
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, body)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(body, &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}

	// Fetch the published key set (as a third party would) and pick the signing key.
	keysResp, err := http.Get(h.ts.URL + "/v1/keys/public")
	if err != nil {
		t.Fatalf("GET keys: %v", err)
	}
	defer keysResp.Body.Close()
	var set signing.JWKS
	if err := json.NewDecoder(keysResp.Body).Decode(&set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	var found bool
	for _, j := range set.Keys {
		if j.Kid == dec.Signature.KeyID {
			pub, err := signing.PublicKeyFromJWK(j)
			if err != nil {
				t.Fatalf("jwk: %v", err)
			}
			if err := signing.Verify(dec, pub); err != nil {
				t.Fatalf("decision failed to verify: %v", err)
			}
			// Tamper: flipping the verdict must break verification.
			tampered := dec
			tampered.Verdict = contractsv1.VerdictDeny
			if err := signing.Verify(tampered, pub); err == nil {
				t.Error("tampered decision still verified")
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("signing key %q not published", dec.Signature.KeyID)
	}
}

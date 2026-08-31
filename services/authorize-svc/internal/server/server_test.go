package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
)

// testAuthn builds an Authenticator over the given key store and a fresh in-memory
// nonce store, with test-friendly skew.
func testAuthn(keys auth.KeyStore) *auth.Authenticator {
	return auth.New(keys, auth.NewMemNonceStore(), auth.Config{
		MaxSkew:  5 * time.Minute,
		NonceTTL: 10 * time.Minute,
	})
}

// testLimiter is a fresh in-memory limiter (generous default tiers) for tests that
// are not exercising rate limiting.
func testLimiter() ratelimit.Limiter { return ratelimit.NewMemLimiter(nil) }

// testServer builds a Server with an empty key store — for tests that do not hit the
// authenticated /v1/authorize route (health, routing).
func testServer(checks ...Check) *Server {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return New(log, BuildInfo{Version: "test", Commit: "abc", Date: "now"},
		testAuthorizer{}, testAuthn(auth.NewMemKeyStore()), testLimiter(), ratelimit.DefaultTiers(), checks...)
}

func TestHealth_OK(t *testing.T) {
	srv := testServer(
		Check{Name: "postgres", Ping: func(context.Context) error { return nil }},
		Check{Name: "redis", Ping: func(context.Context) error { return nil }},
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var body healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q, want ok", body.Status)
	}
	if body.Build.Version != "test" {
		t.Errorf("build.version = %q, want test", body.Build.Version)
	}
	for _, name := range []string{"postgres", "redis"} {
		if body.Checks[name] != "ok" {
			t.Errorf("checks[%s] = %q, want ok", name, body.Checks[name])
		}
	}
}

func TestHealth_DependencyDown(t *testing.T) {
	srv := testServer(
		Check{Name: "postgres", Ping: func(context.Context) error { return nil }},
		Check{Name: "redis", Ping: func(context.Context) error { return errors.New("conn refused") }},
	)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rr.Code)
	}
	var body healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Status != "degraded" {
		t.Errorf("status = %q, want degraded", body.Status)
	}
}

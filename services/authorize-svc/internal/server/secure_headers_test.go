package server

import (
	"net/http"
	"testing"
)

// Every response carries the defense-in-depth headers (TRD §20), even unauthenticated
// ones like /health.
func TestSecureHeaders_Present(t *testing.T) {
	h := newCPHarness(t)
	resp, err := http.Get(h.ts.URL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer resp.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
}

// A handler that sets its own Cache-Control still wins over the middleware defaults
// (the public JWKS route is cacheable).
func TestSecureHeaders_HandlerCacheControlWins(t *testing.T) {
	h := newCPHarness(t)
	resp, err := http.Get(h.ts.URL + "/v1/keys/public")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want the handler's value", cc)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("secure headers should still be present on the JWKS response")
	}
}

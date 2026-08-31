package server

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/ratelimit"
)

// fixedClock pins the limiter's clock so every request in a test lands in the same
// window, letting a small cap be driven past deterministically without real waiting.
func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// TestRateLimit_BurstCapReturns429 drives a key past its per-second burst cap and
// asserts 429 + Retry-After, while requests under the cap are unaffected.
func TestRateLimit_BurstCapReturns429(t *testing.T) {
	// Burst cap 3/s; per-minute high enough not to interfere.
	tiers := ratelimit.TierTable{testTier: {PerMinute: 1000, PerSecond: 3}}
	limiter := ratelimit.NewMemLimiter(fixedClock(time.Unix(1_700_000_000, 0)))
	h := newAuthHarnessWith(t, limiter, tiers)

	// First 3 in the second are allowed.
	for i := 0; i < 3; i++ {
		resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body: %s", i+1, resp.StatusCode, body)
		}
	}

	// 4th trips the burst cap.
	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("4th request: status = %d, want 429; body: %s", resp.StatusCode, body)
	}
	assertProblemCode(t, body, codeRateLimited)
	assertRetryAfter(t, resp, 1, 1)
}

// TestRateLimit_PerMinuteWindowReturns429 drives a key past its per-minute window and
// asserts 429 + a sane Retry-After.
func TestRateLimit_PerMinuteWindowReturns429(t *testing.T) {
	// Per-minute cap 5; burst high enough not to interfere.
	tiers := ratelimit.TierTable{testTier: {PerMinute: 5, PerSecond: 100}}
	limiter := ratelimit.NewMemLimiter(fixedClock(time.Unix(1_700_000_000, 0)))
	h := newAuthHarnessWith(t, limiter, tiers)

	for i := 0; i < 5; i++ {
		resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body: %s", i+1, resp.StatusCode, body)
		}
	}

	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("6th request: status = %d, want 429; body: %s", resp.StatusCode, body)
	}
	assertProblemCode(t, body, codeRateLimited)
	// Window reset is at most 60s away and at least 1s.
	assertRetryAfter(t, resp, 1, 60)
}

// TestRateLimit_UnderLimitUnaffected confirms a key comfortably under its limits is
// never throttled.
func TestRateLimit_UnderLimitUnaffected(t *testing.T) {
	tiers := ratelimit.TierTable{testTier: {PerMinute: 60, PerSecond: 10}}
	limiter := ratelimit.NewMemLimiter(fixedClock(time.Unix(1_700_000_000, 0)))
	h := newAuthHarnessWith(t, limiter, tiers)

	for i := 0; i < 8; i++ {
		resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200; body: %s", i+1, resp.StatusCode, body)
		}
	}
}

// assertRetryAfter checks the Retry-After header is present and within [lo, hi] secs.
func assertRetryAfter(t *testing.T, resp *http.Response, lo, hi int) {
	t.Helper()
	raw := resp.Header.Get("Retry-After")
	if raw == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("Retry-After = %q, not an integer", raw)
	}
	if secs < lo || secs > hi {
		t.Errorf("Retry-After = %d, want within [%d,%d]", secs, lo, hi)
	}
}

package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// --- Threat model (TRD §20) --------------------------------------------------

// An oversized body is rejected (413) before any decision is produced — a caller
// cannot exhaust memory or slip a huge payload past the size guard.
func TestThreat_OversizedBodyRejected(t *testing.T) {
	h := newAuthHarness(t)
	// > maxBodyBytes (64 KiB): a valid-looking prefix followed by filler.
	big := `{"agent_id":"a","action":"payment.create","amount":"1.00","currency":"USD","target":{"type":"vendor","id":"` +
		strings.Repeat("x", 70<<10) + `"},"idempotency_key":"idem_big_0001"}`
	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", []byte(big), h.active))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body: %s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("APPROVE")) {
		t.Fatal("oversized request produced a verdict — must never happen")
	}
}

// --- Chaos / graceful degradation (TRD §21) ---------------------------------

type errAuthorizer struct{}

func (errAuthorizer) Authorize(context.Context, string, contractsv1.AuthorizeRequest, bool) (contractsv1.Decision, error) {
	return contractsv1.Decision{}, errors.New("engine unavailable")
}

// When the decision engine cannot produce a decision, the service returns 503 and
// NEVER a silent APPROVE (the core safety invariant).
func TestChaos_EngineErrorNeverSilentApprove(t *testing.T) {
	h := newAuthHarnessFull(t, testLimiter(), generousTiers(), func(*signing.Signer) Authorizer { return errAuthorizer{} })
	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body: %s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte("APPROVE")) || bytes.Contains(body, []byte(`"verdict"`)) {
		t.Fatalf("engine failure produced a verdict: %s", body)
	}
}

type errLimiter struct{}

func (errLimiter) Allow(context.Context, string, ratelimit.Limits) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("rate limiter backend down")
}

// When the rate limiter's backend is down, the limiter fails OPEN (availability over
// strictness) — the request is served rather than 500'd. This never affects decision
// correctness; it only means a limit check was skipped, which is logged.
func TestChaos_RateLimiterDownFailsOpen(t *testing.T) {
	h := newAuthHarnessWith(t, errLimiter{}, generousTiers())
	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open); body: %s", resp.StatusCode, body)
	}
}

func generousTiers() ratelimit.TierTable {
	return ratelimit.TierTable{"default": {PerMinute: 1_000_000, PerSecond: 1_000_000}}
}

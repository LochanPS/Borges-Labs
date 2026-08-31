// Package ratelimit implements per-key rate limiting for the decision plane
// (TRD §11, ROADMAP Task 1.3).
//
// Two in-app layers, both keyed by the authenticated key id, both tier-driven:
//
//   - Sliding window (per-minute): a fixed-window counter per (key, minute) via an
//     atomic Redis INCR+EXPIRE. Bounds sustained throughput.
//   - Burst cap (per-second): a 1-second-window counter per (key, second), default
//     ≤10 req/s. Bounds instantaneous spikes.
//
// The third layer — a per-IP throttle — is deliberately NOT built here. It belongs at
// the edge (load balancer / API gateway / WAF), where the true client IP is known and
// abusive IPs can be blocked before they reach the app. See docs/rate-limiting.md.
//
// On exceed the caller returns 429 with a Retry-After. The limiter itself never
// writes HTTP; it returns a Decision the HTTP layer renders.
//
// Concurrency: the Redis implementation increments atomically, so N parallel requests
// against one key cannot exceed the cap (each INCR sees a consistent counter). The
// in-memory implementation used in tests takes a mutex for the same guarantee.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limits are the per-key ceilings for one tier.
type Limits struct {
	PerMinute int // sliding-window ceiling; 0 disables the window layer
	PerSecond int // burst ceiling; 0 disables the burst layer
}

// Scope names which layer rejected a request (surfaced for debugging/telemetry).
const (
	ScopeWindow = "window" // per-minute sliding window
	ScopeBurst  = "burst"  // per-second burst cap
)

// Decision is the outcome of an Allow check.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration // how long to wait before retrying (only when !Allowed)
	Scope      string        // which layer decided (only when !Allowed)
	Limit      int           // the ceiling that applied
	Remaining  int           // approximate remaining in the window (when Allowed)
}

// Limiter checks whether a request for keyID is allowed under lim.
type Limiter interface {
	Allow(ctx context.Context, keyID string, lim Limits) (Decision, error)
}

// TierTable maps a tier name to its limits, with a required "default" fallback.
type TierTable map[string]Limits

// DefaultTiers is the built-in tier table. Tune per product/pricing.
func DefaultTiers() TierTable {
	return TierTable{
		"default": {PerMinute: 60, PerSecond: 10},
		"pro":     {PerMinute: 600, PerSecond: 50},
		"free":    {PerMinute: 20, PerSecond: 5},
	}
}

// Resolve returns the limits for a tier, falling back to "default", then to a safe
// built-in if even "default" is absent.
func (t TierTable) Resolve(tier string) Limits {
	if l, ok := t[tier]; ok {
		return l
	}
	if l, ok := t["default"]; ok {
		return l
	}
	return Limits{PerMinute: 60, PerSecond: 10}
}

// retryAfterForMinute is the whole seconds until the current minute-window resets.
func retryAfterForMinute(now time.Time) time.Duration {
	rem := 60 - (now.Unix() % 60)
	if rem <= 0 {
		rem = 1
	}
	return time.Duration(rem) * time.Second
}

// --- in-memory limiter (tests / local dev) -----------------------------------

// MemLimiter is a mutex-guarded fixed-window limiter with the same semantics as the
// Redis one. It is concurrency-safe and used by the hermetic tests.
type MemLimiter struct {
	mu      sync.Mutex
	windows map[string]*counter // per-key minute counter
	bursts  map[string]*counter // per-key second counter
	now     func() time.Time
}

type counter struct {
	epoch int64 // window index (unix-minute or unix-second)
	count int
}

// NewMemLimiter builds an in-memory limiter using the given clock (nil → time.Now).
func NewMemLimiter(now func() time.Time) *MemLimiter {
	if now == nil {
		now = time.Now
	}
	return &MemLimiter{
		windows: make(map[string]*counter),
		bursts:  make(map[string]*counter),
		now:     now,
	}
}

// Allow implements Limiter. Burst is checked (and consumed) first so a burst
// rejection does not also consume the per-minute budget.
func (l *MemLimiter) Allow(_ context.Context, keyID string, lim Limits) (Decision, error) {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if lim.PerSecond > 0 {
		n := hit(l.bursts, keyID, now.Unix())
		if n > lim.PerSecond {
			return Decision{Allowed: false, RetryAfter: time.Second, Scope: ScopeBurst, Limit: lim.PerSecond}, nil
		}
	}
	if lim.PerMinute > 0 {
		n := hit(l.windows, keyID, now.Unix()/60)
		if n > lim.PerMinute {
			return Decision{Allowed: false, RetryAfter: retryAfterForMinute(now), Scope: ScopeWindow, Limit: lim.PerMinute}, nil
		}
		return Decision{Allowed: true, Limit: lim.PerMinute, Remaining: lim.PerMinute - n}, nil
	}
	return Decision{Allowed: true}, nil
}

// hit increments the counter for key in the given epoch, resetting it when the epoch
// rolls over, and returns the new count.
func hit(m map[string]*counter, key string, epoch int64) int {
	c, ok := m[key]
	if !ok || c.epoch != epoch {
		c = &counter{epoch: epoch, count: 0}
		m[key] = c
	}
	c.count++
	return c.count
}

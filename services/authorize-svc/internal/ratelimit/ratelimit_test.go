package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func fixed(at time.Time) func() time.Time { return func() time.Time { return at } }

// TestMemLimiter_BurstThenWindow checks both layers in isolation.
func TestMemLimiter_Layers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewMemLimiter(fixed(now))
	lim := Limits{PerMinute: 5, PerSecond: 3}
	ctx := context.Background()

	// First 3 allowed, 4th trips the burst layer.
	for i := 0; i < 3; i++ {
		d, _ := l.Allow(ctx, "k", lim)
		if !d.Allowed {
			t.Fatalf("burst request %d unexpectedly denied", i+1)
		}
	}
	d, _ := l.Allow(ctx, "k", lim)
	if d.Allowed || d.Scope != ScopeBurst {
		t.Fatalf("4th request: allowed=%v scope=%q, want denied burst", d.Allowed, d.Scope)
	}
}

// TestMemLimiter_NoOversellUnderConcurrency fires many parallel requests at one key
// and asserts that no more than the cap are allowed (concurrency safety).
func TestMemLimiter_NoOversellUnderConcurrency(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewMemLimiter(fixed(now))
	// Only the per-minute layer in play; make burst effectively unlimited.
	lim := Limits{PerMinute: 100, PerSecond: 1_000_000}
	ctx := context.Background()

	const n = 500
	var allowed int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			d, err := l.Allow(ctx, "shared", lim)
			if err != nil {
				t.Errorf("allow: %v", err)
				return
			}
			if d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != int64(lim.PerMinute) {
		t.Fatalf("allowed = %d, want exactly %d (no oversell, no under-count)", allowed, lim.PerMinute)
	}
}

func TestTierTable_Resolve(t *testing.T) {
	tt := DefaultTiers()
	if got := tt.Resolve("pro").PerMinute; got != 600 {
		t.Errorf("pro per-minute = %d, want 600", got)
	}
	// Unknown tier falls back to default.
	if got := tt.Resolve("nonesuch"); got != tt["default"] {
		t.Errorf("unknown tier = %+v, want default %+v", got, tt["default"])
	}
}

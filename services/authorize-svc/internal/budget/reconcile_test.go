package budget

import (
	"context"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/hold"
)

// ACCEPTANCE: a TTL-expired hold is released back to the counter by the reconciler.
func TestReconciler_ReleasesExpired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	counter := NewMemCounter()
	hs := hold.NewMemStore().WithClock(func() time.Time { return now })
	// A reserver placing a short-lived hold.
	r := NewReserver(counter, hs, 10*time.Minute).WithClock(func() time.Time { return now })
	ctx := context.Background()

	req := areq("40.00")
	req.EvaluatedAt = "" // use the injected clock
	if res := r.Reserve(ctx, "org1", "d1", req, decl("100.00")); res.Outcome != engine.BudgetWithinLimit {
		t.Fatalf("reserve = %v, want WithinLimit", res.Outcome)
	}
	key := counterKey("org1", "monthly", WindowKey("month", now))
	if got, _ := counter.Get(ctx, key); got != 4000 {
		t.Fatalf("counter after reserve = %d, want 4000", got)
	}

	rc := NewReconciler(counter, hs, nil, 0).WithClock(func() time.Time { return now.Add(11 * time.Minute) })
	// Advance the hold store's clock too so the hold is past its expiry.
	hs.WithClock(func() time.Time { return now.Add(11 * time.Minute) })

	n, err := rc.ReleaseExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("ReleaseExpired = %d, err=%v, want 1", n, err)
	}
	if got, _ := counter.Get(ctx, key); got != 0 {
		t.Errorf("counter after expiry release = %d, want 0", got)
	}
	// Idempotent: a second pass finds nothing and does not double-release.
	if n, _ := rc.ReleaseExpired(ctx); n != 0 {
		t.Errorf("second ReleaseExpired = %d, want 0", n)
	}
}

// ACCEPTANCE: reconciliation rebuilds a drifted counter from the ledger (source of truth).
func TestReconciler_RebuildWindow(t *testing.T) {
	counter := NewMemCounter()
	hs := hold.NewMemStore()
	r := NewReserver(counter, hs, time.Hour)
	ctx := context.Background()

	r.Reserve(ctx, "org1", "d1", areq("30.00"), decl("1000.00"))
	r.Reserve(ctx, "org1", "d2", areq("20.00"), decl("1000.00"))
	key := counterKey("org1", "monthly", "2026-09")

	// Simulate drift (e.g. a Redis restart lost the counter).
	counter.Set(ctx, key, 999999, time.Hour)

	rc := NewReconciler(counter, hs, nil, 0)
	if err := rc.RebuildWindow(ctx, "org1", "monthly", "2026-09", "month"); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got, _ := counter.Get(ctx, key); got != 5000 {
		t.Errorf("counter after rebuild = %d, want 5000 (30+20 from ledger)", got)
	}
}

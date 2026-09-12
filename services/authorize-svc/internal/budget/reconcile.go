package budget

import (
	"context"
	"log/slog"
	"time"

	"github.com/trust-infra/authorize-svc/internal/hold"
)

// Reconciler keeps the Redis counter consistent with the reservation ledger (the source
// of truth), off the hot path (ROADMAP §3.2). It does two things:
//   - Release TTL-expired holds: a held reservation past its expiry is transitioned to
//     expired (in the ledger) and its amount decremented from the counter — so a
//     crashed caller that never captured/voided cannot leak budget.
//   - Rebuild a drifted counter: recompute a window's counter from the ledger
//     (held + captured spend). Corrects any divergence, e.g. after a Redis restart.
type Reconciler struct {
	counter Counter
	holds   hold.Store
	log     *slog.Logger
	batch   int
	now     func() time.Time
}

// NewReconciler builds a reconciler. batch bounds how many expired holds one pass
// releases (0 => a sane default).
func NewReconciler(counter Counter, holds hold.Store, log *slog.Logger, batch int) *Reconciler {
	if batch <= 0 {
		batch = 256
	}
	return &Reconciler{counter: counter, holds: holds, log: log, batch: batch, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock overrides the clock (tests).
func (rc *Reconciler) WithClock(now func() time.Time) *Reconciler { rc.now = now; return rc }

// Run releases expired holds on an interval until ctx is cancelled.
func (rc *Reconciler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := rc.ReleaseExpired(ctx); err != nil && rc.log != nil {
				rc.log.Warn("budget reconcile: release expired failed", "err", err)
			} else if n > 0 && rc.log != nil {
				rc.log.Info("budget reconcile: released expired holds", "count", n)
			}
		}
	}
}

// ReleaseExpired transitions due holds to expired and decrements their counters. Each
// hold is expired (and thus released) exactly once, because ExpireDue only returns the
// rows it transitioned this call. Returns how many were released.
func (rc *Reconciler) ReleaseExpired(ctx context.Context) (int, error) {
	due, err := rc.holds.ExpireDue(ctx, rc.now(), rc.batch)
	if err != nil {
		return 0, err
	}
	for _, h := range due {
		amount, ok := toCents(h.Amount)
		if !ok {
			continue
		}
		if err := rc.counter.Release(ctx, counterKey(h.OrgID, h.BudgetID, h.WindowKey), amount); err != nil && rc.log != nil {
			rc.log.Warn("budget reconcile: counter release failed", "err", err, "decision_id", h.DecisionID)
		}
	}
	return len(due), nil
}

// RebuildWindow recomputes one window's counter from the ledger (held + captured spend)
// and writes it back — the drift-correction path. TTL is refreshed to the window's TTL.
func (rc *Reconciler) RebuildWindow(ctx context.Context, orgID, budgetID, windowKey, window string) error {
	active, err := rc.holds.ListActiveByWindow(ctx, orgID, budgetID, windowKey)
	if err != nil {
		return err
	}
	var sum int64
	for _, h := range active {
		if c, ok := toCents(h.Amount); ok {
			sum += c
		}
	}
	return rc.counter.Set(ctx, counterKey(orgID, budgetID, windowKey), sum, windowTTL(window))
}

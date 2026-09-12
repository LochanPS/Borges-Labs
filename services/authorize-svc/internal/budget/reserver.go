package budget

import (
	"context"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/hold"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Reserver enforces budgets: it atomically reserves against the counter (no oversell)
// and durably records the reservation in the hold ledger (source of truth). It
// implements engine.BudgetReserver (the Reserve call the engine folds into a verdict)
// and the capture/void lifecycle the HTTP handlers use.
type Reserver struct {
	counter Counter
	holds   hold.Store
	holdTTL time.Duration
	now     func() time.Time
}

// NewReserver builds a Reserver. holdTTL must match the engine's hold TTL so the
// reservation's expiry lines up with the capture_within obligation's expires_at.
func NewReserver(counter Counter, holds hold.Store, holdTTL time.Duration) *Reserver {
	if holdTTL <= 0 {
		holdTTL = engine.DefaultHoldTTL
	}
	return &Reserver{counter: counter, holds: holds, holdTTL: holdTTL, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock overrides the clock (tests).
func (r *Reserver) WithClock(now func() time.Time) *Reserver { r.now = now; return r }

// Reserve implements engine.BudgetReserver. It reserves req.Amount against the budget's
// current window and, on success, records a held reservation. On a counter error or an
// unparseable amount it returns BudgetUnavailable (fail closed); on cap exceedance it
// returns BudgetExceeded (nothing reserved).
func (r *Reserver) Reserve(ctx context.Context, orgID, decisionID string, req contractsv1.AuthorizeRequest, b engine.BudgetDecl) engine.BudgetResult {
	t := r.now()
	if parsed, err := time.Parse(time.RFC3339, req.EvaluatedAt); err == nil {
		t = parsed.UTC()
	}
	wk := WindowKey(b.Window, t)

	amount, ok := toCents(req.Amount)
	limit, ok2 := toCents(b.Limit)
	if !ok || !ok2 {
		// A budget/amount we cannot represent exactly is treated as unavailable rather
		// than silently approved.
		return engine.BudgetResult{Outcome: engine.BudgetUnavailable, WindowKey: wk}
	}

	key := counterKey(orgID, b.ID, wk)
	reserved, prior, err := r.counter.Reserve(ctx, key, amount, limit, windowTTL(b.Window), windowSticky(b.Window))
	if err != nil {
		return engine.BudgetResult{Outcome: engine.BudgetUnavailable, WindowKey: wk}
	}
	res := engine.BudgetResult{SpendToDate: centsToStr(prior), Limit: b.Limit, WindowKey: wk}
	if !reserved {
		res.Outcome = engine.BudgetExceeded
		return res
	}

	// Durably record the reservation (source of truth). If the ledger write fails, undo
	// the Redis reservation so the counter does not carry a phantom hold, and fail closed.
	h := &hold.Hold{
		DecisionID: decisionID,
		OrgID:      orgID,
		AgentID:    req.AgentID,
		BudgetID:   b.ID,
		Window:     b.Window,
		WindowKey:  wk,
		Amount:     req.Amount,
		Currency:   req.Currency,
		State:      hold.StateHeld,
		CreatedAt:  t,
		ExpiresAt:  t.Add(r.holdTTL),
	}
	if err := r.holds.Place(ctx, h); err != nil {
		_ = r.counter.Release(ctx, key, amount)
		return engine.BudgetResult{Outcome: engine.BudgetUnavailable, WindowKey: wk}
	}
	res.Outcome = engine.BudgetWithinLimit
	return res
}

// Capture commits the hold (payment succeeded). The reserved amount stays counted, so
// the counter is unchanged. Idempotent.
func (r *Reserver) Capture(ctx context.Context, orgID, decisionID string) (*hold.Hold, error) {
	return r.holds.Capture(ctx, orgID, decisionID)
}

// Void releases the hold (payment failed/aborted) and decrements the counter exactly
// once (only when this call performed the held→voided transition). Idempotent.
func (r *Reserver) Void(ctx context.Context, orgID, decisionID string) (*hold.Hold, error) {
	h, released, err := r.holds.Void(ctx, orgID, decisionID)
	if err != nil {
		return nil, err
	}
	if released {
		amount, ok := toCents(h.Amount)
		if ok {
			// Best-effort: a counter under-release leaves drift the reconciler corrects.
			_ = r.counter.Release(ctx, counterKey(h.OrgID, h.BudgetID, h.WindowKey), amount)
		}
	}
	return h, nil
}

// Get returns the current hold state.
func (r *Reserver) Get(ctx context.Context, orgID, decisionID string) (*hold.Hold, error) {
	return r.holds.Get(ctx, orgID, decisionID)
}

var _ engine.BudgetReserver = (*Reserver)(nil)

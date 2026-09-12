// Package hold implements the two-phase budget reservation lifecycle (ROADMAP A#2,
// Task 3.1). A budget-affecting APPROVE places a HOLD (reservation) with a TTL; the
// caller then commits it (capture, on payment success) or releases it (void, on
// failure). An untouched hold auto-expires at its TTL and is released, so a crashed
// caller cannot leak budget.
//
// State machine (addressed by the decision id — the hold_ref on the capture_within
// obligation):
//
//	                 capture
//	    held ─────────────────────▶ captured   (committed; terminal)
//	     │  │
//	     │  └────── void ─────────▶ voided      (released; terminal)
//	     │
//	     └──── TTL elapsed ───────▶ expired     (released; terminal)
//
//	capture:  held→captured; captured→captured (idempotent); voided/expired→conflict; missing→404
//	void:     held→voided;   voided→voided   (idempotent); expired→voided (already released);
//	          captured→conflict; missing→404
//
// The reservation ARITHMETIC (decrementing an atomic budget counter, enforcing the cap,
// reconciling to Postgres) is Phase 3.2. Phase 3.1 is the mechanism: a durable,
// idempotent, TTL-bounded lifecycle the counter work plugs into.
package hold

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is a hold's lifecycle state.
type State string

const (
	StateHeld     State = "held"
	StateCaptured State = "captured"
	StateVoided   State = "voided"
	StateExpired  State = "expired"
)

// Hold is a budget reservation for one decision. It is addressed by (OrgID, DecisionID);
// the decision id is the hold_ref the caller was handed on the capture_within obligation.
type Hold struct {
	DecisionID string    `json:"decision_id"`
	OrgID      string    `json:"org_id"`
	AgentID    string    `json:"agent_id"`
	BudgetID   string    `json:"budget_id"`
	Window     string    `json:"window"`      // day | month | rolling
	WindowKey  string    `json:"window_key"`  // concrete period, e.g. 2026-09
	Amount     string    `json:"amount"`
	Currency   string    `json:"currency"`
	State      State     `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	CapturedAt time.Time `json:"captured_at,omitempty"`
	VoidedAt   time.Time `json:"voided_at,omitempty"`
}

// ErrNotFound is returned when no hold matches (org, decision_id) — including a Redis
// hold whose TTL already elapsed and was evicted.
var ErrNotFound = errors.New("hold: not found")

// ConflictError is an illegal state transition (e.g. capturing a voided hold). The
// server maps it to HTTP 409.
type ConflictError struct {
	From   State
	Action string
	Reason string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("hold: cannot %s a %s hold: %s", e.Action, e.From, e.Reason)
}

func conflict(from State, action, reason string) *ConflictError {
	return &ConflictError{From: from, Action: action, Reason: reason}
}

// Store persists holds and applies the lifecycle transitions atomically. Place is
// idempotent by (org, decision_id) so a retried authorize never double-holds. Capture
// and Void are idempotent so a client retry is safe. Implementations: Redis (TTL-backed,
// production) and an in-memory fake for hermetic tests.
type Store interface {
	Place(ctx context.Context, h *Hold) error
	Capture(ctx context.Context, orgID, decisionID string) (*Hold, error)
	// Void releases a held hold. released is true only when THIS call performed the
	// held→voided transition, so the caller decrements the budget counter exactly once
	// (an idempotent repeat or a void of an already-released hold reports released=false).
	Void(ctx context.Context, orgID, decisionID string) (h *Hold, released bool, err error)
	Get(ctx context.Context, orgID, decisionID string) (*Hold, error)
	// ExpireDue transitions up to limit holds that are still held past their ExpiresAt
	// to expired and returns exactly those it transitioned (so the reconciler releases
	// each one's counter exactly once). Reservation source of truth for TTL release.
	ExpireDue(ctx context.Context, now time.Time, limit int) ([]*Hold, error)
	// ListActiveByWindow returns the held+captured holds for a budget window (used to
	// rebuild a drifted counter from the source of truth).
	ListActiveByWindow(ctx context.Context, orgID, budgetID, windowKey string) ([]*Hold, error)
}

// MemStore is an in-memory Store for hermetic tests. Expiry is evaluated against an
// injectable clock, so a test can advance time to exercise TTL release deterministically.
type MemStore struct {
	mu    sync.Mutex
	now   func() time.Time
	holds map[string]*Hold // key: org|decisionID
}

// NewMemStore builds an empty in-memory hold store.
func NewMemStore() *MemStore {
	return &MemStore{now: func() time.Time { return time.Now().UTC() }, holds: make(map[string]*Hold)}
}

// WithClock overrides the clock (tests).
func (m *MemStore) WithClock(now func() time.Time) *MemStore { m.now = now; return m }

func key(org, id string) string { return org + "|" + id }

// Place records a new hold; re-placing an existing (org, decision_id) is an idempotent
// no-op (the retried authorize returns the same decision and the same hold).
func (m *MemStore) Place(_ context.Context, h *Hold) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(h.OrgID, h.DecisionID)
	if _, ok := m.holds[k]; ok {
		return nil // idempotent
	}
	cp := *h
	if cp.State == "" {
		cp.State = StateHeld
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = m.now()
	}
	m.holds[k] = &cp
	return nil
}

// resolve returns the stored hold with its expiry applied (a held hold past ExpiresAt
// is transitioned to expired in place before any action is taken).
func (m *MemStore) resolve(org, id string) (*Hold, bool) {
	h, ok := m.holds[key(org, id)]
	if !ok {
		return nil, false
	}
	if h.State == StateHeld && !h.ExpiresAt.IsZero() && !m.now().Before(h.ExpiresAt) {
		h.State = StateExpired
	}
	return h, true
}

func (m *MemStore) Capture(_ context.Context, org, id string) (*Hold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.resolve(org, id)
	if !ok {
		return nil, ErrNotFound
	}
	switch h.State {
	case StateHeld:
		h.State = StateCaptured
		h.CapturedAt = m.now()
	case StateCaptured:
		// idempotent no-op
	case StateVoided:
		return nil, conflict(StateVoided, "capture", "the hold was voided")
	case StateExpired:
		return nil, conflict(StateExpired, "capture", "the hold expired before capture")
	}
	out := *h
	return &out, nil
}

func (m *MemStore) Void(_ context.Context, org, id string) (*Hold, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.resolve(org, id)
	if !ok {
		return nil, false, ErrNotFound
	}
	released := false
	switch h.State {
	case StateHeld:
		h.State = StateVoided
		h.VoidedAt = m.now()
		released = true // this call released the reservation → caller decrements the counter
	case StateVoided:
		// idempotent no-op
	case StateExpired:
		// already released by the reconciler at TTL; acknowledge as voided, no re-release
		h.State = StateVoided
		h.VoidedAt = m.now()
	case StateCaptured:
		return nil, false, conflict(StateCaptured, "void", "the hold was already captured")
	}
	out := *h
	return &out, released, nil
}

// ExpireDue transitions held holds past their ExpiresAt to expired and returns them.
func (m *MemStore) ExpireDue(_ context.Context, now time.Time, limit int) ([]*Hold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Hold
	for _, h := range m.holds {
		if limit > 0 && len(out) >= limit {
			break
		}
		if h.State == StateHeld && !h.ExpiresAt.IsZero() && !now.Before(h.ExpiresAt) {
			h.State = StateExpired
			cp := *h
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ListActiveByWindow returns the held+captured holds for a budget window.
func (m *MemStore) ListActiveByWindow(_ context.Context, org, budgetID, windowKey string) ([]*Hold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Hold
	for _, h := range m.holds {
		if h.OrgID == org && h.BudgetID == budgetID && h.WindowKey == windowKey &&
			(h.State == StateHeld || h.State == StateCaptured) {
			cp := *h
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *MemStore) Get(_ context.Context, org, id string) (*Hold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.resolve(org, id)
	if !ok {
		return nil, ErrNotFound
	}
	out := *h
	return &out, nil
}

var _ Store = (*MemStore)(nil)

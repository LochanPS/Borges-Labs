package hold

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newHold(id string, expires time.Time) *Hold {
	return &Hold{
		DecisionID: id, OrgID: "org1", AgentID: "agent-a", BudgetID: "monthly",
		Amount: "100.00", Currency: "USD", State: StateHeld, ExpiresAt: expires,
	}
}

// ACCEPTANCE: authorize→capture commits.
func TestCapture_CommitsHeld(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	m.Place(ctx, newHold("d1", time.Now().Add(time.Hour)))
	h, err := m.Capture(ctx, "org1", "d1")
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if h.State != StateCaptured {
		t.Errorf("state = %s, want captured", h.State)
	}
}

// ACCEPTANCE: authorize→void releases.
func TestVoid_ReleasesHeld(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	m.Place(ctx, newHold("d1", time.Now().Add(time.Hour)))
	h, err := m.Void(ctx, "org1", "d1")
	if err != nil || h.State != StateVoided {
		t.Fatalf("void: state=%v err=%v", h.State, err)
	}
}

// Capture and void are idempotent (safe under client retries).
func TestCaptureVoid_Idempotent(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	m.Place(ctx, newHold("d1", time.Now().Add(time.Hour)))
	if _, err := m.Capture(ctx, "org1", "d1"); err != nil {
		t.Fatalf("capture1: %v", err)
	}
	if h, err := m.Capture(ctx, "org1", "d1"); err != nil || h.State != StateCaptured {
		t.Errorf("capture2 (idempotent): state=%v err=%v", h.State, err)
	}

	m.Place(ctx, newHold("d2", time.Now().Add(time.Hour)))
	if _, err := m.Void(ctx, "org1", "d2"); err != nil {
		t.Fatalf("void1: %v", err)
	}
	if h, err := m.Void(ctx, "org1", "d2"); err != nil || h.State != StateVoided {
		t.Errorf("void2 (idempotent): state=%v err=%v", h.State, err)
	}
}

// ACCEPTANCE: capture after void is rejected (and void after capture).
func TestConflictingTransitions(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()

	m.Place(ctx, newHold("d1", time.Now().Add(time.Hour)))
	m.Void(ctx, "org1", "d1")
	_, err := m.Capture(ctx, "org1", "d1")
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Errorf("capture-after-void err = %v, want ConflictError", err)
	}

	m.Place(ctx, newHold("d2", time.Now().Add(time.Hour)))
	m.Capture(ctx, "org1", "d2")
	_, err = m.Void(ctx, "org1", "d2")
	if !errors.As(err, &ce) {
		t.Errorf("void-after-capture err = %v, want ConflictError", err)
	}
}

// ACCEPTANCE: authorize→(no action)→TTL expiry releases; a later capture fails.
func TestExpiry_ReleasesAndBlocksCapture(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	m := NewMemStore().WithClock(func() time.Time { return now })
	ctx := context.Background()
	m.Place(ctx, newHold("d1", now.Add(10*time.Minute)))

	// Advance past the TTL.
	now = now.Add(11 * time.Minute)

	if h, _ := m.Get(ctx, "org1", "d1"); h.State != StateExpired {
		t.Errorf("state after TTL = %s, want expired", h.State)
	}
	_, err := m.Capture(ctx, "org1", "d1")
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Errorf("capture-after-expiry err = %v, want ConflictError", err)
	}
}

// ACCEPTANCE: re-placing the same hold is a no-op (retried authorize never double-holds).
func TestPlace_Idempotent(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	m.Place(ctx, newHold("d1", time.Now().Add(time.Hour)))
	// A second Place with different fields must not overwrite the original.
	dup := newHold("d1", time.Now().Add(time.Hour))
	dup.Amount = "999.00"
	m.Place(ctx, dup)
	h, _ := m.Get(ctx, "org1", "d1")
	if h.Amount != "100.00" {
		t.Errorf("amount = %s, want original 100.00 (Place must be idempotent)", h.Amount)
	}
}

// Capture/void of an unknown hold is not-found.
func TestUnknownHold(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	if _, err := m.Capture(ctx, "org1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("capture unknown err = %v, want ErrNotFound", err)
	}
}

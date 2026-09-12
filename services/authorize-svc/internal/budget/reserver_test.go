package budget

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/hold"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

func decl(limit string) engine.BudgetDecl {
	return engine.BudgetDecl{ID: "monthly", Window: "month", Limit: limit, Currency: "USD"}
}

func areq(amount string) contractsv1.AuthorizeRequest {
	return contractsv1.AuthorizeRequest{
		AgentID: "agent-a", Action: "payment.create", Amount: amount, Currency: "USD",
		Target:      contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
		EvaluatedAt: "2026-09-15T12:00:00Z",
	}
}

func newReserver() (*Reserver, *hold.MemStore) {
	hs := hold.NewMemStore()
	return NewReserver(NewMemCounter(), hs, 15*time.Minute), hs
}

// Within-limit reserves and records a held hold; an exceeding reserve is denied and
// records nothing.
func TestReserver_WithinThenExceeded(t *testing.T) {
	r, hs := newReserver()
	ctx := context.Background()

	res := r.Reserve(ctx, "org1", "d1", areq("60.00"), decl("100.00"))
	if res.Outcome != engine.BudgetWithinLimit {
		t.Fatalf("first reserve = %v, want WithinLimit", res.Outcome)
	}
	if res.SpendToDate != "0.00" {
		t.Errorf("spend_to_date = %q, want 0.00", res.SpendToDate)
	}

	res2 := r.Reserve(ctx, "org1", "d2", areq("60.00"), decl("100.00"))
	if res2.Outcome != engine.BudgetExceeded {
		t.Errorf("second reserve = %v, want Exceeded (60+60 > 100)", res2.Outcome)
	}
	if res2.SpendToDate != "60.00" {
		t.Errorf("spend_to_date = %q, want 60.00", res2.SpendToDate)
	}

	// Only the within-limit reservation was recorded.
	if _, err := hs.Get(ctx, "org1", "d1"); err != nil {
		t.Errorf("d1 hold missing: %v", err)
	}
	if _, err := hs.Get(ctx, "org1", "d2"); !errors.Is(err, hold.ErrNotFound) {
		t.Errorf("d2 hold should not exist (exceeded): %v", err)
	}
}

// ACCEPTANCE: N concurrent authorizations against one cap never oversell.
func TestReserver_NoOversell(t *testing.T) {
	r, _ := newReserver()
	ctx := context.Background()
	const limit = "100.00" // 10000 cents
	const each = "10.00"    // 1000 cents → at most 10 fit

	var wg sync.WaitGroup
	var mu sync.Mutex
	approved := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := r.Reserve(ctx, "org1", "d"+strconv.Itoa(i), areq(each), decl(limit))
			if res.Outcome == engine.BudgetWithinLimit {
				mu.Lock()
				approved++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if approved != 10 {
		t.Errorf("approved = %d, want exactly 10 (no oversell, no under-fill)", approved)
	}
	got, _ := r.counter.Get(ctx, counterKey("org1", "monthly", "2026-09"))
	if got != 10000 {
		t.Errorf("counter = %d cents, want 10000 (== limit, never above)", got)
	}
}

// ACCEPTANCE: window rollover resets — a new month is a fresh cap.
func TestReserver_WindowRollover(t *testing.T) {
	r, _ := newReserver()
	ctx := context.Background()

	// Fill September to the cap.
	if res := r.Reserve(ctx, "org1", "d1", areq("100.00"), decl("100.00")); res.Outcome != engine.BudgetWithinLimit {
		t.Fatalf("september reserve = %v, want WithinLimit", res.Outcome)
	}
	if res := r.Reserve(ctx, "org1", "d2", areq("1.00"), decl("100.00")); res.Outcome != engine.BudgetExceeded {
		t.Fatalf("september over-cap = %v, want Exceeded", res.Outcome)
	}

	// October (new window key) starts fresh.
	oct := areq("100.00")
	oct.EvaluatedAt = "2026-10-01T00:00:00Z"
	if res := r.Reserve(ctx, "org1", "d3", oct, decl("100.00")); res.Outcome != engine.BudgetWithinLimit {
		t.Errorf("october reserve = %v, want WithinLimit (rollover resets)", res.Outcome)
	}
}

// ACCEPTANCE: Redis (counter) unavailable → fail closed (UNAVAILABLE), never within.
func TestReserver_CounterUnavailableFailsClosed(t *testing.T) {
	r := NewReserver(errCounter{}, hold.NewMemStore(), time.Minute)
	res := r.Reserve(context.Background(), "org1", "d1", areq("1.00"), decl("100.00"))
	if res.Outcome != engine.BudgetUnavailable {
		t.Errorf("outcome = %v, want Unavailable (fail closed)", res.Outcome)
	}
}

// Void releases the counter; capture leaves it counted.
func TestReserver_VoidReleasesCaptureKeeps(t *testing.T) {
	r, _ := newReserver()
	ctx := context.Background()
	key := counterKey("org1", "monthly", "2026-09")

	r.Reserve(ctx, "org1", "dv", areq("40.00"), decl("100.00"))
	r.Reserve(ctx, "org1", "dc", areq("30.00"), decl("100.00"))
	if got, _ := r.counter.Get(ctx, key); got != 7000 {
		t.Fatalf("counter after 2 reserves = %d, want 7000", got)
	}

	if _, err := r.Void(ctx, "org1", "dv"); err != nil {
		t.Fatalf("void: %v", err)
	}
	if got, _ := r.counter.Get(ctx, key); got != 3000 {
		t.Errorf("counter after void = %d, want 3000 (40 released)", got)
	}
	// Idempotent void must not double-release.
	r.Void(ctx, "org1", "dv")
	if got, _ := r.counter.Get(ctx, key); got != 3000 {
		t.Errorf("counter after repeat void = %d, want still 3000", got)
	}

	if _, err := r.Capture(ctx, "org1", "dc"); err != nil {
		t.Fatalf("capture: %v", err)
	}
	if got, _ := r.counter.Get(ctx, key); got != 3000 {
		t.Errorf("counter after capture = %d, want 3000 (captured spend persists)", got)
	}
}

// errCounter always fails Reserve, to exercise fail-closed.
type errCounter struct{}

func (errCounter) Reserve(context.Context, string, int64, int64, time.Duration, bool) (bool, int64, error) {
	return false, 0, errors.New("redis down")
}
func (errCounter) Release(context.Context, string, int64) error           { return nil }
func (errCounter) Set(context.Context, string, int64, time.Duration) error { return nil }
func (errCounter) Get(context.Context, string) (int64, error)             { return 0, nil }

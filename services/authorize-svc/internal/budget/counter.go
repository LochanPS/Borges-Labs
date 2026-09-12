package budget

import (
	"context"
	"sync"
	"time"
)

// Counter is the atomic budget accumulator. Reserve is a single atomic check-and-add:
// it increments the counter by amount only if the result stays within limit, and
// reports whether it did plus the prior value (for evidence). This atomicity is what
// prevents oversell under concurrency. Release decrements (void/expiry); Set replaces
// the value (reconciliation rebuild from the ledger).
type Counter interface {
	Reserve(ctx context.Context, key string, amountCents, limitCents int64, ttl time.Duration, sticky bool) (reserved bool, priorCents int64, err error)
	Release(ctx context.Context, key string, amountCents int64) error
	Set(ctx context.Context, key string, cents int64, ttl time.Duration) error
	Get(ctx context.Context, key string) (int64, error)
}

// MemCounter is an in-memory Counter for hermetic tests. Its mutex makes Reserve a true
// atomic check-and-add, so the concurrency/no-oversell test exercises the same
// invariant the Redis Lua guarantees in production. TTL is not modeled (window rollover
// is exercised via distinct window keys, not counter expiry).
type MemCounter struct {
	mu   sync.Mutex
	vals map[string]int64
}

// NewMemCounter builds an empty in-memory counter.
func NewMemCounter() *MemCounter { return &MemCounter{vals: make(map[string]int64)} }

func (m *MemCounter) Reserve(_ context.Context, key string, amount, limit int64, _ time.Duration, _ bool) (bool, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prior := m.vals[key]
	if prior+amount > limit {
		return false, prior, nil
	}
	m.vals[key] = prior + amount
	return true, prior, nil
}

func (m *MemCounter) Release(_ context.Context, key string, amount int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.vals[key] - amount
	if v < 0 {
		v = 0
	}
	m.vals[key] = v
	return nil
}

func (m *MemCounter) Set(_ context.Context, key string, cents int64, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vals[key] = cents
	return nil
}

func (m *MemCounter) Get(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.vals[key], nil
}

var _ Counter = (*MemCounter)(nil)

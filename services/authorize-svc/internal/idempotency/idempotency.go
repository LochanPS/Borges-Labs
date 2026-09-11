// Package idempotency caches a decision by (org, idempotency_key) so a repeated
// authorize request returns the SAME decision instead of a fresh one.
//
// Scope (Task 1.7): the decision plane has no money-moving side effects yet
// (budgets/capture land in Phase 3), so idempotency here only guarantees a
// consistent RESPONSE for a repeated key — the same decision_id, verdict, and
// signature. The store is best-effort on the hot path: a lookup miss or backend
// error never blocks a decision (fail-open on the cache, never on the policy).
//
// Known MVP limitation: two concurrent requests with the same key can both miss
// the cache and each compute a decision (deterministic, so same verdict — but
// different decision_ids). Phase 3 replaces this with an atomic reserve-on-key
// once a write actually reserves budget; until then there is nothing to double-spend.
package idempotency

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// key namespaces the (org, idempotency_key) pair in the shared keyspace.
func key(orgID, idemKey string) string {
	return "idem:" + orgID + ":" + idemKey
}

// Redis is the shared, cross-instance idempotency cache (hot-path store — TRD §13).
// Entries expire after TTL so a key is only idempotent within a bounded window.
type Redis struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedis builds a Redis-backed cache. A non-positive ttl defaults to 24h.
func NewRedis(client *redis.Client, ttl time.Duration) *Redis {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Redis{client: client, ttl: ttl}
}

// Lookup returns the cached decision for the key, or ok=false on a miss.
func (r *Redis) Lookup(ctx context.Context, orgID, idemKey string) (contractsv1.Decision, bool, error) {
	raw, err := r.client.Get(ctx, key(orgID, idemKey)).Bytes()
	if err == redis.Nil {
		return contractsv1.Decision{}, false, nil
	}
	if err != nil {
		return contractsv1.Decision{}, false, fmt.Errorf("idempotency: get: %w", err)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(raw, &dec); err != nil {
		// A corrupt entry is treated as a miss rather than an error, so a bad cache
		// value can never wedge the hot path.
		return contractsv1.Decision{}, false, nil
	}
	return dec, true, nil
}

// Save stores the decision under the key with the configured TTL, overwriting any
// existing value (a repeat key resolves to the most recent stored decision).
func (r *Redis) Save(ctx context.Context, orgID, idemKey string, dec contractsv1.Decision) error {
	raw, err := json.Marshal(dec)
	if err != nil {
		return fmt.Errorf("idempotency: marshal: %w", err)
	}
	if err := r.client.Set(ctx, key(orgID, idemKey), raw, r.ttl).Err(); err != nil {
		return fmt.Errorf("idempotency: set: %w", err)
	}
	return nil
}

// Mem is an in-memory idempotency cache for hermetic tests (same seam pattern as
// the other stores). It ignores TTL — tests do not exercise expiry.
type Mem struct {
	mu sync.Mutex
	m  map[string]contractsv1.Decision
}

// NewMem builds an empty in-memory cache.
func NewMem() *Mem { return &Mem{m: make(map[string]contractsv1.Decision)} }

// Lookup returns the cached decision for the key, or ok=false on a miss.
func (m *Mem) Lookup(_ context.Context, orgID, idemKey string) (contractsv1.Decision, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dec, ok := m.m[key(orgID, idemKey)]
	return dec, ok, nil
}

// Save stores the decision under the key.
func (m *Mem) Save(_ context.Context, orgID, idemKey string, dec contractsv1.Decision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key(orgID, idemKey)] = dec
	return nil
}

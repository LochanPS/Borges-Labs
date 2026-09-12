package hold

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// holdKeyPrefix namespaces hold hashes in Redis.
const holdKeyPrefix = "hold:"

// RedisStore is the production Store. Each hold is a Redis hash keyed
// hold:<org>:<decision_id> with an absolute expiry (PEXPIREAT) at the hold's TTL, so an
// untouched hold is auto-released by Redis itself — no sweeper needed. Transitions run
// as Lua scripts so a concurrent capture/void race resolves atomically.
//
// Expiry note: when the TTL elapses Redis evicts the key, so a later capture/void sees
// "missing" and returns ErrNotFound. That is the released state for the Redis backing
// (the MemStore instead tracks an explicit `expired` state for deterministic tests);
// either way an expired hold can no longer be captured.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore wraps a Redis client.
func NewRedisStore(client *redis.Client) *RedisStore { return &RedisStore{client: client} }

func holdKey(org, id string) string { return holdKeyPrefix + org + ":" + id }

// placeScript creates the hold hash only if absent (idempotent), setting an absolute
// expiry so the reservation auto-releases at its TTL.
var placeScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1],
  'state','held','agent',ARGV[1],'budget',ARGV[2],'amount',ARGV[3],
  'currency',ARGV[4],'created_at',ARGV[5],'expires_at',ARGV[6])
redis.call('PEXPIREAT', KEYS[1], ARGV[7])
return 1`)

// captureScript commits a held hold (idempotent for an already-captured one) and
// reports the resulting/current state, or 'missing' when the key is gone.
var captureScript = redis.NewScript(`
local st = redis.call('HGET', KEYS[1], 'state')
if not st then return 'missing' end
if st == 'held' then
  redis.call('HSET', KEYS[1], 'state', 'captured', 'captured_at', ARGV[1])
  return 'captured'
end
return st`)

// voidScript releases a held hold (idempotent for an already-voided one).
var voidScript = redis.NewScript(`
local st = redis.call('HGET', KEYS[1], 'state')
if not st then return 'missing' end
if st == 'held' then
  redis.call('HSET', KEYS[1], 'state', 'voided', 'voided_at', ARGV[1])
  return 'voided'
end
return st`)

func (s *RedisStore) Place(ctx context.Context, h *Hold) error {
	created := h.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := placeScript.Run(ctx, s.client, []string{holdKey(h.OrgID, h.DecisionID)},
		h.AgentID, h.BudgetID, h.Amount, h.Currency,
		strconv.FormatInt(created.Unix(), 10),
		strconv.FormatInt(h.ExpiresAt.Unix(), 10),
		strconv.FormatInt(h.ExpiresAt.UnixMilli(), 10),
	).Result()
	if err != nil {
		return fmt.Errorf("hold: place: %w", err)
	}
	return nil
}

func (s *RedisStore) Capture(ctx context.Context, org, id string) (*Hold, error) {
	return s.transition(ctx, captureScript, "capture", org, id)
}

func (s *RedisStore) Void(ctx context.Context, org, id string) (*Hold, error) {
	return s.transition(ctx, voidScript, "void", org, id)
}

// transition runs a capture/void script and maps the result to a Hold or a typed error.
func (s *RedisStore) transition(ctx context.Context, script *redis.Script, action, org, id string) (*Hold, error) {
	res, err := script.Run(ctx, s.client, []string{holdKey(org, id)},
		strconv.FormatInt(time.Now().UTC().Unix(), 10)).Text()
	if err != nil {
		return nil, fmt.Errorf("hold: %s: %w", action, err)
	}
	st := State(res)
	if res == "missing" {
		return nil, ErrNotFound
	}
	// Illegal transitions: capturing a voided hold, or voiding a captured one.
	if action == "capture" && st == StateVoided {
		return nil, conflict(StateVoided, "capture", "the hold was voided")
	}
	if action == "void" && st == StateCaptured {
		return nil, conflict(StateCaptured, "void", "the hold was already captured")
	}
	return s.Get(ctx, org, id)
}

func (s *RedisStore) Get(ctx context.Context, org, id string) (*Hold, error) {
	m, err := s.client.HGetAll(ctx, holdKey(org, id)).Result()
	if err != nil {
		return nil, fmt.Errorf("hold: get: %w", err)
	}
	if len(m) == 0 {
		return nil, ErrNotFound
	}
	h := &Hold{
		DecisionID: id,
		OrgID:      org,
		AgentID:    m["agent"],
		BudgetID:   m["budget"],
		Amount:     m["amount"],
		Currency:   m["currency"],
		State:      State(m["state"]),
		CreatedAt:  unixField(m["created_at"]),
		ExpiresAt:  unixField(m["expires_at"]),
		CapturedAt: unixField(m["captured_at"]),
		VoidedAt:   unixField(m["voided_at"]),
	}
	return h, nil
}

func unixField(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

var _ Store = (*RedisStore)(nil)

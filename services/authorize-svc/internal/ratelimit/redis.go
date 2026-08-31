package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrExpireScript atomically increments a counter and sets its TTL on first
// creation, returning the new count. Doing both in one Lua eval closes the
// INCR-then-EXPIRE race where a crash between the two would leave a key with no TTL
// (a permanently stuck counter).
var incrExpireScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return c
`)

// RedisLimiter is the production Limiter. Counters live in Redis so the limit is
// enforced across all decision-plane instances, not per-process.
type RedisLimiter struct {
	client *redis.Client
	now    func() time.Time
}

// NewRedisLimiter wraps a Redis client.
func NewRedisLimiter(client *redis.Client) *RedisLimiter {
	return &RedisLimiter{client: client, now: time.Now}
}

// Allow implements Limiter. Burst (per-second) is checked and consumed first so a
// burst rejection does not also consume the per-minute budget.
func (l *RedisLimiter) Allow(ctx context.Context, keyID string, lim Limits) (Decision, error) {
	now := l.now()

	if lim.PerSecond > 0 {
		sec := now.Unix()
		key := "rl:sec:" + keyID + ":" + strconv.FormatInt(sec, 10)
		n, err := l.incr(ctx, key, 2*time.Second) // 2s TTL: brief overlap, self-cleaning
		if err != nil {
			return Decision{}, err
		}
		if n > int64(lim.PerSecond) {
			return Decision{Allowed: false, RetryAfter: time.Second, Scope: ScopeBurst, Limit: lim.PerSecond}, nil
		}
	}

	if lim.PerMinute > 0 {
		min := now.Unix() / 60
		key := "rl:min:" + keyID + ":" + strconv.FormatInt(min, 10)
		n, err := l.incr(ctx, key, 61*time.Second) // just over a minute so it survives the window
		if err != nil {
			return Decision{}, err
		}
		if n > int64(lim.PerMinute) {
			return Decision{Allowed: false, RetryAfter: retryAfterForMinute(now), Scope: ScopeWindow, Limit: lim.PerMinute}, nil
		}
		return Decision{Allowed: true, Limit: lim.PerMinute, Remaining: lim.PerMinute - int(n)}, nil
	}

	return Decision{Allowed: true}, nil
}

// incr runs the atomic INCR+EXPIRE and returns the new counter value.
func (l *RedisLimiter) incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := incrExpireScript.Run(ctx, l.client, []string{key}, int(ttl.Seconds())).Int64()
	if err != nil {
		return 0, fmt.Errorf("ratelimit: incr: %w", err)
	}
	return n, nil
}

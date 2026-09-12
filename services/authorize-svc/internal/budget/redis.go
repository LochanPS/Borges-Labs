package budget

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCounter is the production Counter. Reserve is a Lua script so the read, the
// limit check, and the increment are one atomic step server-side — the property that
// makes N concurrent authorizations against one cap unable to oversell (TRD §17).
type RedisCounter struct {
	client *redis.Client
}

// NewRedisCounter wraps a Redis client.
func NewRedisCounter(client *redis.Client) *RedisCounter { return &RedisCounter{client: client} }

// reserveScript: increment by amount iff current+amount <= limit; set the TTL on first
// creation (sticky calendar window) or refresh it every time (sliding rolling window).
// Returns {reserved (1/0), prior}.
var reserveScript = redis.NewScript(`
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local amt = tonumber(ARGV[1])
local lim = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local sticky = ARGV[4] == '1'
if cur + amt > lim then
  return {0, cur}
end
local existed = redis.call('EXISTS', KEYS[1]) == 1
redis.call('INCRBY', KEYS[1], amt)
if (not sticky) or (not existed) then
  redis.call('PEXPIRE', KEYS[1], ttl)
end
return {1, cur}`)

func (c *RedisCounter) Reserve(ctx context.Context, key string, amount, limit int64, ttl time.Duration, sticky bool) (bool, int64, error) {
	stickyArg := "0"
	if sticky {
		stickyArg = "1"
	}
	res, err := reserveScript.Run(ctx, c.client, []string{key},
		amount, limit, ttl.Milliseconds(), stickyArg).Int64Slice()
	if err != nil {
		return false, 0, fmt.Errorf("budget: reserve: %w", err)
	}
	if len(res) != 2 {
		return false, 0, fmt.Errorf("budget: reserve: unexpected result %v", res)
	}
	return res[0] == 1, res[1], nil
}

// releaseScript decrements by amount, floored at zero, and never resurrects a
// TTL-expired key (only touches an existing one).
var releaseScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
local amt = tonumber(ARGV[1])
local nv = cur - amt
if nv < 0 then nv = 0 end
redis.call('SET', KEYS[1], nv, 'KEEPTTL')
return nv`)

func (c *RedisCounter) Release(ctx context.Context, key string, amount int64) error {
	if err := releaseScript.Run(ctx, c.client, []string{key}, amount).Err(); err != nil {
		return fmt.Errorf("budget: release: %w", err)
	}
	return nil
}

func (c *RedisCounter) Set(ctx context.Context, key string, cents int64, ttl time.Duration) error {
	if err := c.client.Set(ctx, key, cents, ttl).Err(); err != nil {
		return fmt.Errorf("budget: set: %w", err)
	}
	return nil
}

func (c *RedisCounter) Get(ctx context.Context, key string) (int64, error) {
	v, err := c.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("budget: get: %w", err)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("budget: get parse: %w", err)
	}
	return n, nil
}

var _ Counter = (*RedisCounter)(nil)

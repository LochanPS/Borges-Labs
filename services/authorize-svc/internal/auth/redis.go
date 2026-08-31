package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// noncePrefix namespaces per-key nonce entries in Redis.
const noncePrefix = "authnonce:"

// keyCachePrefix namespaces cached key records in Redis.
const keyCachePrefix = "authkey:"

// RedisNonceStore is the production NonceStore. It uses SET NX EX for an atomic
// "remember if new" so concurrent requests with the same nonce race safely: exactly
// one wins the SET and is fresh; the rest are rejected as replays.
type RedisNonceStore struct {
	client *redis.Client
}

// NewRedisNonceStore wraps a Redis client.
func NewRedisNonceStore(client *redis.Client) *RedisNonceStore {
	return &RedisNonceStore{client: client}
}

// Remember implements NonceStore atomically via SET NX.
func (s *RedisNonceStore) Remember(ctx context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	// keyID is server-derived and nonce is length-bounded by the caller; both are
	// safe to embed. Redis keys are binary-safe regardless.
	k := noncePrefix + keyID + ":" + nonce
	ok, err := s.client.SetNX(ctx, k, 1, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("auth: nonce setnx: %w", err)
	}
	return ok, nil
}

// RedisKeyCache caches key records with a TTL to keep key lookups off Postgres on
// the hot path (TRD §11: 5-min cache). A miss falls through to the source store.
type RedisKeyCache struct {
	client *redis.Client
}

// NewRedisKeyCache wraps a Redis client.
func NewRedisKeyCache(client *redis.Client) *RedisKeyCache {
	return &RedisKeyCache{client: client}
}

// Get returns the cached record for a key id, or ok=false on a miss. A corrupt cache
// entry is treated as a miss (and left for the TTL to evict).
func (c *RedisKeyCache) Get(ctx context.Context, keyID string) (KeyRecord, bool, error) {
	b, err := c.client.Get(ctx, keyCachePrefix+keyID).Bytes()
	if errors.Is(err, redis.Nil) {
		return KeyRecord{}, false, nil
	}
	if err != nil {
		return KeyRecord{}, false, fmt.Errorf("auth: key cache get: %w", err)
	}
	var rec KeyRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return KeyRecord{}, false, nil // treat corrupt entry as a miss
	}
	return rec, true, nil
}

// Set caches a record under the given TTL.
func (c *RedisKeyCache) Set(ctx context.Context, rec KeyRecord, ttl time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("auth: key cache marshal: %w", err)
	}
	if err := c.client.Set(ctx, keyCachePrefix+rec.KeyID, b, ttl).Err(); err != nil {
		return fmt.Errorf("auth: key cache set: %w", err)
	}
	return nil
}

// Invalidate drops a cached record immediately (e.g. on revocation) so a revoke does
// not wait out the TTL.
func (c *RedisKeyCache) Invalidate(ctx context.Context, keyID string) error {
	if err := c.client.Del(ctx, keyCachePrefix+keyID).Err(); err != nil {
		return fmt.Errorf("auth: key cache del: %w", err)
	}
	return nil
}

// KeyCache is the caching seam CachedKeyStore depends on (RedisKeyCache implements it).
type KeyCache interface {
	Get(ctx context.Context, keyID string) (KeyRecord, bool, error)
	Set(ctx context.Context, rec KeyRecord, ttl time.Duration) error
}

// CachedKeyStore fronts a source KeyStore (Postgres) with a short-TTL cache. On a
// cache or source error it returns the error so the authenticator can fail closed;
// it never fabricates a record.
//
// Revocation note (TRD §11 "revoke = immediate"): a cached record can be up to TTL
// stale. MVP relies on the short TTL; revocation should also call
// RedisKeyCache.Invalidate to evict immediately. A published invalidation channel is
// the production upgrade.
type CachedKeyStore struct {
	cache  KeyCache
	source KeyStore
	ttl    time.Duration
}

// NewCachedKeyStore composes a cache in front of a source store.
func NewCachedKeyStore(cache KeyCache, source KeyStore, ttl time.Duration) *CachedKeyStore {
	return &CachedKeyStore{cache: cache, source: source, ttl: ttl}
}

// LookupByID implements KeyStore: cache first, then source, populating the cache on a
// hit from source.
func (s *CachedKeyStore) LookupByID(ctx context.Context, keyID string) (KeyRecord, error) {
	if rec, ok, err := s.cache.Get(ctx, keyID); err != nil {
		return KeyRecord{}, err
	} else if ok {
		return rec, nil
	}

	rec, err := s.source.LookupByID(ctx, keyID)
	if err != nil {
		return KeyRecord{}, err // includes ErrKeyNotFound (not cached — see revoke note)
	}
	if err := s.cache.Set(ctx, rec, s.ttl); err != nil {
		// A cache write failure must not fail an otherwise-valid lookup; the next
		// request simply misses again. Surface nothing but the record.
		return rec, nil
	}
	return rec, nil
}

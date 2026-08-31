// Package store holds the decision plane's connections to its backing stores.
//
// Boundary rule (TRD §3): the decision plane only READs cached state and writes
// async audit; it never makes a synchronous call to the control plane. At this
// scaffold stage there is no business logic — just connect + Ping + Close.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Postgres is the source-of-truth store (orgs, keys, policies, decisions).
type Postgres struct {
	Pool *pgxpool.Pool
}

// NewPostgres opens a connection pool and verifies it with a Ping.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: new pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Postgres{Pool: pool}, nil
}

// Ping checks Postgres liveness.
func (p *Postgres) Ping(ctx context.Context) error { return p.Pool.Ping(ctx) }

// Close releases the pool.
func (p *Postgres) Close() { p.Pool.Close() }

// Redis is the hot-path store (key cache, rate limit, nonce, budget counters).
type Redis struct {
	Client *redis.Client
}

// NewRedis parses the URL, connects, and verifies it with a Ping.
func NewRedis(ctx context.Context, url string) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	client := redis.NewClient(opt)
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return &Redis{Client: client}, nil
}

// Ping checks Redis liveness.
func (r *Redis) Ping(ctx context.Context) error { return r.Client.Ping(ctx).Err() }

// Close releases the client.
func (r *Redis) Close() error { return r.Client.Close() }

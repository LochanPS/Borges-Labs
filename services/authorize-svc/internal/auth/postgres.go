package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresKeyStore is the source-of-truth KeyStore. It reads the api_keys table with
// parameterized queries only (TRD §11: ORM/parameterized queries, never string
// concatenation).
//
// Schema: deploy/migrations/0001_api_keys.sql.
type PostgresKeyStore struct {
	pool *pgxpool.Pool
}

// NewPostgresKeyStore wraps a pgx pool.
func NewPostgresKeyStore(pool *pgxpool.Pool) *PostgresKeyStore {
	return &PostgresKeyStore{pool: pool}
}

// LookupByID implements KeyStore, returning ErrKeyNotFound when no row matches.
func (s *PostgresKeyStore) LookupByID(ctx context.Context, keyID string) (KeyRecord, error) {
	const q = `
		SELECT key_id, key_sha256, org_id, tier, env, status, shadow
		FROM api_keys
		WHERE key_id = $1`

	var rec KeyRecord
	err := s.pool.QueryRow(ctx, q, keyID).Scan(
		&rec.KeyID, &rec.KeyHashHex, &rec.OrgID, &rec.Tier, &rec.Env, &rec.Status, &rec.Shadow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyRecord{}, ErrKeyNotFound
	}
	if err != nil {
		return KeyRecord{}, fmt.Errorf("auth: key lookup: %w", err)
	}
	return rec, nil
}

// Insert persists a new key record. Used by the keygen tool and seed fixtures; the
// raw key is never stored, only its hash (already computed into rec.KeyHashHex).
func (s *PostgresKeyStore) Insert(ctx context.Context, rec KeyRecord) error {
	const q = `
		INSERT INTO api_keys (key_id, key_sha256, org_id, tier, env, status, shadow)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.pool.Exec(ctx, q, rec.KeyID, rec.KeyHashHex, rec.OrgID, rec.Tier, rec.Env, rec.Status, rec.Shadow)
	if err != nil {
		return fmt.Errorf("auth: key insert: %w", err)
	}
	return nil
}

// CreateKey implements KeyAdmin: persist a freshly minted key with an explicit
// created_at (hash only; the raw key is never stored).
func (s *PostgresKeyStore) CreateKey(ctx context.Context, rec KeyRecord, createdAt time.Time) error {
	const q = `
		INSERT INTO api_keys (key_id, key_sha256, org_id, tier, env, status, shadow, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.pool.Exec(ctx, q, rec.KeyID, rec.KeyHashHex, rec.OrgID, rec.Tier, rec.Env, rec.Status, rec.Shadow, createdAt)
	if err != nil {
		return fmt.Errorf("auth: key create: %w", err)
	}
	return nil
}

// ListKeys implements KeyAdmin: the org's keys, newest first. Never selects the hash.
func (s *PostgresKeyStore) ListKeys(ctx context.Context, orgID string) ([]KeyInfo, error) {
	const q = `
		SELECT key_id, org_id, tier, env, status, shadow, created_at, revoked_at
		FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("auth: key list: %w", err)
	}
	defer rows.Close()
	out := make([]KeyInfo, 0)
	for rows.Next() {
		var ki KeyInfo
		if err := rows.Scan(&ki.KeyID, &ki.OrgID, &ki.Tier, &ki.Env, &ki.Status, &ki.Shadow, &ki.CreatedAt, &ki.RevokedAt); err != nil {
			return nil, fmt.Errorf("auth: key list scan: %w", err)
		}
		out = append(out, ki)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: key list rows: %w", err)
	}
	return out, nil
}

// RevokeKey implements KeyAdmin: flip a key to revoked within its org, returning the
// updated info. ErrKeyNotFound when no such key belongs to the org.
func (s *PostgresKeyStore) RevokeKey(ctx context.Context, orgID, keyID string, at time.Time) (KeyInfo, error) {
	const q = `
		UPDATE api_keys SET status = 'revoked', revoked_at = $3
		WHERE org_id = $1 AND key_id = $2
		RETURNING key_id, org_id, tier, env, status, shadow, created_at, revoked_at`
	var ki KeyInfo
	err := s.pool.QueryRow(ctx, q, orgID, keyID, at).Scan(
		&ki.KeyID, &ki.OrgID, &ki.Tier, &ki.Env, &ki.Status, &ki.Shadow, &ki.CreatedAt, &ki.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return KeyInfo{}, ErrKeyNotFound
	}
	if err != nil {
		return KeyInfo{}, fmt.Errorf("auth: key revoke: %w", err)
	}
	return ki, nil
}

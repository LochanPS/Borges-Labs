package auth

import (
	"context"
	"errors"
	"fmt"

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

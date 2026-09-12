package policyctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the source-of-truth Store (schema: deploy/migrations/0003_policies.sql).
// All queries are parameterized (TRD §11). policy_versions is append-only at the DB
// layer (trigger), so PutVersion only ever INSERTs — never updates a signed version.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a connection pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) CreatePolicy(ctx context.Context, p *Policy) error {
	agents, rules, err := marshalDoc(p.Agents, p.Rules)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO policies (id, org_id, name, agents, rules, status, active_version_hash, created_at, updated_at)
		VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9)
		ON CONFLICT (id) DO NOTHING
		RETURNING id`
	var got string
	err = s.pool.QueryRow(ctx, q,
		p.ID, p.OrgID, p.Name, agents, rules, string(p.Status), nullIfEmpty(p.ActiveVersionHash), p.CreatedAt, p.UpdatedAt,
	).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPolicyExists
	}
	if err != nil {
		return fmt.Errorf("policyctl: insert policy: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetPolicy(ctx context.Context, orgID, id string) (*Policy, error) {
	const q = `
		SELECT id, org_id, name, agents, rules, status, active_version_hash, created_at, updated_at
		FROM policies WHERE org_id=$1 AND id=$2`
	var (
		p                    Policy
		agentsJSON, rulesJSON []byte
		active               *string
		status               string
	)
	err := s.pool.QueryRow(ctx, q, orgID, id).Scan(
		&p.ID, &p.OrgID, &p.Name, &agentsJSON, &rulesJSON, &status, &active, &p.CreatedAt, &p.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("policyctl: get policy: %w", err)
	}
	p.Status = Status(status)
	if active != nil {
		p.ActiveVersionHash = *active
	}
	if err := unmarshalDoc(agentsJSON, rulesJSON, &p.Agents, &p.Rules); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) UpdatePolicy(ctx context.Context, p *Policy) error {
	agents, rules, err := marshalDoc(p.Agents, p.Rules)
	if err != nil {
		return err
	}
	const q = `
		UPDATE policies
		SET name=$3, agents=$4::jsonb, rules=$5::jsonb, status=$6, active_version_hash=$7, updated_at=$8
		WHERE org_id=$1 AND id=$2`
	tag, err := s.pool.Exec(ctx, q,
		p.OrgID, p.ID, p.Name, agents, rules, string(p.Status), nullIfEmpty(p.ActiveVersionHash), p.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("policyctl: update policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

func (s *PostgresStore) PutVersion(ctx context.Context, v *Version) (bool, error) {
	agents, rules, err := marshalDoc(v.Agents, v.Rules)
	if err != nil {
		return false, err
	}
	sigJSON, err := json.Marshal(v.Signature)
	if err != nil {
		return false, fmt.Errorf("policyctl: marshal signature: %w", err)
	}
	const q = `
		INSERT INTO policy_versions (version_hash, policy_id, org_id, name, agents, rules, signature, author, parent_hash, published_at)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb,$8,$9,$10)
		ON CONFLICT (version_hash) DO NOTHING
		RETURNING version_hash`
	var got string
	err = s.pool.QueryRow(ctx, q,
		v.VersionHash, v.PolicyID, v.OrgID, v.Name, agents, rules, string(sigJSON), v.Author, nullIfEmpty(v.ParentHash), v.PublishedAt,
	).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // content-addressed idempotent no-op
	}
	if err != nil {
		return false, fmt.Errorf("policyctl: insert version: %w", err)
	}
	return true, nil
}

func (s *PostgresStore) GetVersion(ctx context.Context, orgID, policyID, versionHash string) (*Version, error) {
	const q = `
		SELECT version_hash, policy_id, org_id, name, agents, rules, signature, author, parent_hash, published_at
		FROM policy_versions WHERE org_id=$1 AND policy_id=$2 AND version_hash=$3`
	v, err := s.scanVersion(s.pool.QueryRow(ctx, q, orgID, policyID, versionHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVersionNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *PostgresStore) ListVersions(ctx context.Context, orgID, policyID string) ([]*Version, error) {
	const q = `
		SELECT version_hash, policy_id, org_id, name, agents, rules, signature, author, parent_hash, published_at
		FROM policy_versions WHERE org_id=$1 AND policy_id=$2 ORDER BY published_at DESC`
	rows, err := s.pool.Query(ctx, q, orgID, policyID)
	if err != nil {
		return nil, fmt.Errorf("policyctl: list versions: %w", err)
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v, err := s.scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policyctl: list versions rows: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) SetActiveBundle(ctx context.Context, ref *BundleRef) error {
	const q = `
		INSERT INTO org_active_bundles (org_id, policy_id, version_hash, updated_at)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (org_id) DO UPDATE
		SET policy_id=EXCLUDED.policy_id, version_hash=EXCLUDED.version_hash, updated_at=EXCLUDED.updated_at`
	if _, err := s.pool.Exec(ctx, q, ref.OrgID, ref.PolicyID, ref.VersionHash, ref.UpdatedAt); err != nil {
		return fmt.Errorf("policyctl: set active bundle: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetActiveBundle(ctx context.Context, orgID string) (*BundleRef, error) {
	const q = `SELECT org_id, policy_id, version_hash, updated_at FROM org_active_bundles WHERE org_id=$1`
	var b BundleRef
	err := s.pool.QueryRow(ctx, q, orgID).Scan(&b.OrgID, &b.PolicyID, &b.VersionHash, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBundleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("policyctl: get active bundle: %w", err)
	}
	return &b, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (s *PostgresStore) scanVersion(row rowScanner) (*Version, error) {
	var (
		v                              Version
		agentsJSON, rulesJSON, sigJSON []byte
		parent                         *string
	)
	if err := row.Scan(
		&v.VersionHash, &v.PolicyID, &v.OrgID, &v.Name, &agentsJSON, &rulesJSON, &sigJSON, &v.Author, &parent, &v.PublishedAt,
	); err != nil {
		return nil, err
	}
	if parent != nil {
		v.ParentHash = *parent
	}
	if err := unmarshalDoc(agentsJSON, rulesJSON, &v.Agents, &v.Rules); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sigJSON, &v.Signature); err != nil {
		return nil, fmt.Errorf("policyctl: unmarshal signature: %w", err)
	}
	return &v, nil
}

func marshalDoc(agents []string, rules []Rule) (string, string, error) {
	a, err := json.Marshal(nonNilStrings(agents))
	if err != nil {
		return "", "", fmt.Errorf("policyctl: marshal agents: %w", err)
	}
	r, err := json.Marshal(nonNilRules(rules))
	if err != nil {
		return "", "", fmt.Errorf("policyctl: marshal rules: %w", err)
	}
	return string(a), string(r), nil
}

func unmarshalDoc(agentsJSON, rulesJSON []byte, agents *[]string, rules *[]Rule) error {
	if err := json.Unmarshal(agentsJSON, agents); err != nil {
		return fmt.Errorf("policyctl: unmarshal agents: %w", err)
	}
	if err := json.Unmarshal(rulesJSON, rules); err != nil {
		return fmt.Errorf("policyctl: unmarshal rules: %w", err)
	}
	return nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

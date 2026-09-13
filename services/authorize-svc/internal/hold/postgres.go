package hold

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the source-of-truth reservation ledger (schema:
// deploy/migrations/0006_budget_reservations.sql). All queries are parameterized.
// State transitions are single-row conditional UPDATEs so an idempotent repeat and a
// concurrent capture/void race resolve to exactly one effective transition.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pgx pool.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) Place(ctx context.Context, h *Hold) error {
	created := h.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	const q = `
		INSERT INTO budget_reservations
		  (org_id, decision_id, agent_id, budget_id, window, window_key, amount, currency, state, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'held',$9,$10)
		ON CONFLICT (org_id, decision_id) DO NOTHING`
	_, err := s.pool.Exec(ctx, q,
		h.OrgID, h.DecisionID, h.AgentID, h.BudgetID, h.Window, h.WindowKey, h.Amount, h.Currency, created, h.ExpiresAt)
	if err != nil {
		return fmt.Errorf("hold: place: %w", err)
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, org, id string) (*Hold, error) {
	const q = `
		SELECT org_id, decision_id, agent_id, budget_id, window, window_key, amount, currency,
		       state, created_at, expires_at, captured_at, voided_at
		FROM budget_reservations WHERE org_id=$1 AND decision_id=$2`
	h, err := scanHold(s.pool.QueryRow(ctx, q, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.effective(ctx, h)
}

// effective transitions a held-but-expired row to expired lazily on read, so a caller
// sees the released state even before the reconciler runs.
func (s *PostgresStore) effective(ctx context.Context, h *Hold) (*Hold, error) {
	if h.State == StateHeld && !h.ExpiresAt.IsZero() && !time.Now().UTC().Before(h.ExpiresAt) {
		h.State = StateExpired
	}
	return h, nil
}

func (s *PostgresStore) Capture(ctx context.Context, org, id string) (*Hold, error) {
	h, err := s.Get(ctx, org, id)
	if err != nil {
		return nil, err
	}
	switch h.State {
	case StateCaptured:
		return h, nil // idempotent
	case StateVoided:
		return nil, conflict(StateVoided, "capture", "the hold was voided")
	case StateExpired:
		return nil, conflict(StateExpired, "capture", "the hold expired before capture")
	}
	// held → captured, but only if it is still held (guards a concurrent void).
	const q = `UPDATE budget_reservations SET state='captured', captured_at=now()
		WHERE org_id=$1 AND decision_id=$2 AND state='held'`
	tag, err := s.pool.Exec(ctx, q, org, id)
	if err != nil {
		return nil, fmt.Errorf("hold: capture: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Someone transitioned it between our read and write — re-resolve.
		return s.Capture(ctx, org, id)
	}
	return s.Get(ctx, org, id)
}

func (s *PostgresStore) Void(ctx context.Context, org, id string) (*Hold, bool, error) {
	h, err := s.Get(ctx, org, id)
	if err != nil {
		return nil, false, err
	}
	switch h.State {
	case StateVoided:
		return h, false, nil // idempotent, already released
	case StateExpired:
		// already released by the reconciler; record the void without re-releasing
		const qe = `UPDATE budget_reservations SET state='voided', voided_at=now()
			WHERE org_id=$1 AND decision_id=$2 AND state='expired'`
		if _, err := s.pool.Exec(ctx, qe, org, id); err != nil {
			return nil, false, fmt.Errorf("hold: void(expired): %w", err)
		}
		out, _ := s.Get(ctx, org, id)
		return out, false, nil
	case StateCaptured:
		return nil, false, conflict(StateCaptured, "void", "the hold was already captured")
	}
	// held → voided; the affected-row count tells us whether THIS call released it.
	const q = `UPDATE budget_reservations SET state='voided', voided_at=now()
		WHERE org_id=$1 AND decision_id=$2 AND state='held'`
	tag, err := s.pool.Exec(ctx, q, org, id)
	if err != nil {
		return nil, false, fmt.Errorf("hold: void: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return s.Void(ctx, org, id) // raced; re-resolve
	}
	out, err := s.Get(ctx, org, id)
	return out, true, err
}

func (s *PostgresStore) ExpireDue(ctx context.Context, now time.Time, limit int) ([]*Hold, error) {
	// Atomically flip a batch of due holds to expired and return exactly those rows, so
	// each is released from the counter exactly once (a later run won't see them again).
	const q = `
		UPDATE budget_reservations SET state='expired'
		WHERE (org_id, decision_id) IN (
			SELECT org_id, decision_id FROM budget_reservations
			WHERE state='held' AND expires_at <= $1
			ORDER BY expires_at LIMIT $2
		)
		RETURNING org_id, decision_id, agent_id, budget_id, window, window_key, amount, currency,
		          state, created_at, expires_at, captured_at, voided_at`
	rows, err := s.pool.Query(ctx, q, now, limit)
	if err != nil {
		return nil, fmt.Errorf("hold: expire due: %w", err)
	}
	defer rows.Close()
	var out []*Hold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListActiveByWindow(ctx context.Context, org, budgetID, windowKey string) ([]*Hold, error) {
	const q = `
		SELECT org_id, decision_id, agent_id, budget_id, window, window_key, amount, currency,
		       state, created_at, expires_at, captured_at, voided_at
		FROM budget_reservations
		WHERE org_id=$1 AND budget_id=$2 AND window_key=$3 AND state IN ('held','captured')`
	rows, err := s.pool.Query(ctx, q, org, budgetID, windowKey)
	if err != nil {
		return nil, fmt.Errorf("hold: list active: %w", err)
	}
	defer rows.Close()
	var out []*Hold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanHold(row rowScanner) (*Hold, error) {
	var (
		h                Hold
		captured, voided *time.Time
	)
	err := row.Scan(
		&h.OrgID, &h.DecisionID, &h.AgentID, &h.BudgetID, &h.Window, &h.WindowKey, &h.Amount, &h.Currency,
		&h.State, &h.CreatedAt, &h.ExpiresAt, &captured, &voided,
	)
	if err != nil {
		return nil, err
	}
	if captured != nil {
		h.CapturedAt = captured.UTC()
	}
	if voided != nil {
		h.VoidedAt = voided.UTC()
	}
	return &h, nil
}

var _ Store = (*PostgresStore)(nil)

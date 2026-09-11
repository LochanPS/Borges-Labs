package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// PostgresStore is the source-of-truth append-only decision log (schema:
// deploy/migrations/0002_decisions.sql). All queries are parameterized (TRD §11).
//
// Field-level encryption (A#10) is applied here at the storage boundary via enc.
// Retention (retain_until) is computed by the caller (the server knows the tier and
// its window) and carried on the Record; the store simply persists it.
type PostgresStore struct {
	pool *pgxpool.Pool
	enc  Encryptor
}

// NewPostgresStore wraps a pool with the field encryptor. A nil Encryptor defaults
// to no-op (plaintext at rest).
func NewPostgresStore(pool *pgxpool.Pool, enc Encryptor) *PostgresStore {
	if enc == nil {
		enc = NopEncryptor{}
	}
	return &PostgresStore{pool: pool, enc: enc}
}

// Append inserts the record with its chain links assigned atomically. A per-org
// advisory lock serializes concurrent appends across instances so the chain stays
// linear; re-appending an existing (org, decision_id) is an idempotent no-op.
func (s *PostgresStore) Append(ctx context.Context, r *Record) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize appends for this org: the chain's tail must not move between the
	// read below and the insert.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, r.OrgID); err != nil {
		return fmt.Errorf("audit: advisory lock: %w", err)
	}

	prev := GenesisPrev
	var last string
	err = tx.QueryRow(ctx,
		`SELECT record_hash FROM decisions WHERE org_id=$1 ORDER BY seq DESC LIMIT 1`, r.OrgID).Scan(&last)
	switch {
	case err == nil:
		prev = last
	case errors.Is(err, pgx.ErrNoRows):
		// first record for this org — genesis prev
	default:
		return fmt.Errorf("audit: read chain tail: %w", err)
	}

	hash, err := ComputeRecordHash(prev, r) // over plaintext
	if err != nil {
		return err
	}

	explanationJSON, err := json.Marshal(nonNilExplanation(r.Explanation))
	if err != nil {
		return fmt.Errorf("audit: marshal explanation: %w", err)
	}
	obligationsJSON, err := json.Marshal(nonNilObligations(r.Obligations))
	if err != nil {
		return fmt.Errorf("audit: marshal obligations: %w", err)
	}
	signatureJSON, err := json.Marshal(r.Signature)
	if err != nil {
		return fmt.Errorf("audit: marshal signature: %w", err)
	}

	amountEnc, err := s.enc.Encrypt(r.Amount)
	if err != nil {
		return err
	}
	targetTypeEnc, err := s.enc.Encrypt(r.TargetType)
	if err != nil {
		return err
	}
	targetIDEnc, err := s.enc.Encrypt(r.TargetID)
	if err != nil {
		return err
	}

	evalTS := parseEvalTS(r.EvaluatedAt)
	var retainUntil *time.Time
	if !r.RetainUntil.IsZero() {
		t := r.RetainUntil.UTC()
		retainUntil = &t
	}

	const q = `
		INSERT INTO decisions (
			decision_id, org_id, api_key_id,
			agent_id, action, currency, jurisdiction,
			amount_enc, target_type_enc, target_id_enc,
			verdict, policy_version_hash, explanation, obligations, signature,
			latency_ms, evaluated_at, evaluated_at_ts, shadow,
			prev_hash, record_hash, retain_until
		) VALUES (
			$1,$2,$3,
			$4,$5,$6,$7,
			$8,$9,$10,
			$11,$12,$13::jsonb,$14::jsonb,$15::jsonb,
			$16,$17,$18,$19,
			$20,$21,$22
		)
		ON CONFLICT (org_id, decision_id) DO NOTHING
		RETURNING seq, created_at`

	var seq int64
	var createdAt time.Time
	err = tx.QueryRow(ctx, q,
		r.DecisionID, r.OrgID, r.APIKeyID,
		r.AgentID, r.Action, r.Currency, r.Jurisdiction,
		amountEnc, targetTypeEnc, targetIDEnc,
		string(r.Verdict), r.PolicyVersionHash, string(explanationJSON), string(obligationsJSON), string(signatureJSON),
		r.LatencyMs, r.EvaluatedAt, evalTS, r.Shadow,
		prev, hash, retainUntil,
	).Scan(&seq, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Conflict: an identical decision_id is already logged. Idempotent no-op.
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}

	r.Seq, r.PrevHash, r.RecordHash, r.CreatedAt = seq, prev, hash, createdAt
	if retainUntil != nil {
		r.RetainUntil = *retainUntil
	}
	return nil
}

// selectColumns is the shared projection for Get/List, in scan order.
const selectColumns = `
	seq, decision_id, org_id, api_key_id,
	agent_id, action, currency, jurisdiction,
	amount_enc, target_type_enc, target_id_enc,
	verdict, policy_version_hash, explanation, obligations, signature,
	latency_ms, evaluated_at, shadow,
	prev_hash, record_hash, retain_until, created_at`

// Get returns the org's record for a decision id, decrypted, or ErrNotFound.
func (s *PostgresStore) Get(ctx context.Context, orgID, decisionID string) (*Record, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+selectColumns+` FROM decisions WHERE org_id=$1 AND decision_id=$2`, orgID, decisionID)
	r, err := s.scan(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// List returns a filtered, paginated page (newest first) of decrypted records.
func (s *PostgresStore) List(ctx context.Context, orgID string, f Filter) (Page, error) {
	limit := clampLimit(f.Limit)

	args := []any{orgID}
	q := `SELECT ` + selectColumns + ` FROM decisions WHERE org_id=$1`
	add := func(cond string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(" AND %s$%d", cond, len(args))
	}
	if f.AgentID != "" {
		add("agent_id=", f.AgentID)
	}
	if f.Verdict != "" {
		add("verdict=", string(f.Verdict))
	}
	if !f.From.IsZero() {
		add("evaluated_at_ts>=", f.From)
	}
	if !f.To.IsZero() {
		add("evaluated_at_ts<", f.To)
	}
	if f.Cursor > 0 {
		add("seq<", f.Cursor)
	}
	// Fetch one extra row to know whether a further page exists.
	args = append(args, limit+1)
	q += fmt.Sprintf(" ORDER BY seq DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return Page{}, fmt.Errorf("audit: list query: %w", err)
	}
	defer rows.Close()

	var page Page
	for rows.Next() {
		r, err := s.scan(rows)
		if err != nil {
			return Page{}, err
		}
		page.Records = append(page.Records, r)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("audit: list rows: %w", err)
	}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		page.NextCursor = page.Records[len(page.Records)-1].Seq
	}
	return page, nil
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scan reads one row into a Record and decrypts its sensitive fields.
func (s *PostgresStore) scan(row rowScanner) (*Record, error) {
	var (
		r                                Record
		verdict                          string
		explanationJSON, obligationsJSON []byte
		signatureJSON                    []byte
		retainUntil                      *time.Time
	)
	err := row.Scan(
		&r.Seq, &r.DecisionID, &r.OrgID, &r.APIKeyID,
		&r.AgentID, &r.Action, &r.Currency, &r.Jurisdiction,
		&r.Amount, &r.TargetType, &r.TargetID,
		&verdict, &r.PolicyVersionHash, &explanationJSON, &obligationsJSON, &signatureJSON,
		&r.LatencyMs, &r.EvaluatedAt, &r.Shadow,
		&r.PrevHash, &r.RecordHash, &retainUntil, &r.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	r.Verdict = contractsv1.Verdict(verdict)
	if err := json.Unmarshal(explanationJSON, &r.Explanation); err != nil {
		return nil, fmt.Errorf("audit: unmarshal explanation: %w", err)
	}
	if err := json.Unmarshal(obligationsJSON, &r.Obligations); err != nil {
		return nil, fmt.Errorf("audit: unmarshal obligations: %w", err)
	}
	if err := json.Unmarshal(signatureJSON, &r.Signature); err != nil {
		return nil, fmt.Errorf("audit: unmarshal signature: %w", err)
	}
	if retainUntil != nil {
		r.RetainUntil = *retainUntil
	}
	if err := decryptInto(s.enc, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func parseEvalTS(s string) time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func nonNilExplanation(e contractsv1.Explanation) contractsv1.Explanation {
	if e.MatchedRules == nil {
		e.MatchedRules = []contractsv1.MatchedRule{}
	}
	return e
}

func nonNilObligations(o []contractsv1.Obligation) []contractsv1.Obligation {
	if o == nil {
		return []contractsv1.Obligation{}
	}
	return o
}

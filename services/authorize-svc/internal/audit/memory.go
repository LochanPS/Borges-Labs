package audit

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore is an in-memory Store for hermetic tests (the same seam pattern as
// auth.NewMemKeyStore / ratelimit.NewMemLimiter). It applies the Encryptor at the
// storage boundary just like Postgres does, so tamper and encryption behavior are
// exercised without a database.
type MemStore struct {
	mu    sync.Mutex
	enc   Encryptor
	now   func() time.Time
	seq   int64
	byOrg map[string][]*Record // insertion order; sensitive fields encrypted at rest
}

// NewMemStore builds an empty in-memory store. A nil Encryptor defaults to no-op.
func NewMemStore(enc Encryptor) *MemStore {
	if enc == nil {
		enc = NopEncryptor{}
	}
	return &MemStore{enc: enc, now: time.Now, byOrg: make(map[string][]*Record)}
}

// Append assigns Seq/PrevHash/RecordHash atomically and stores the record with its
// sensitive fields encrypted. Re-appending an existing (org, decision_id) is an
// idempotent no-op.
func (m *MemStore) Append(_ context.Context, r *Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ex := range m.byOrg[r.OrgID] {
		if ex.DecisionID == r.DecisionID {
			return nil // idempotent
		}
	}

	prev := GenesisPrev
	if tail := m.byOrg[r.OrgID]; len(tail) > 0 {
		prev = tail[len(tail)-1].RecordHash
	}
	hash, err := ComputeRecordHash(prev, r) // over plaintext
	if err != nil {
		return err
	}

	m.seq++
	stored := *r // copy
	stored.Seq = m.seq
	stored.PrevHash = prev
	stored.RecordHash = hash
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = m.now().UTC()
	}
	if err := encryptInto(m.enc, &stored); err != nil {
		return err
	}
	m.byOrg[r.OrgID] = append(m.byOrg[r.OrgID], &stored)

	// Reflect the assigned chain fields back to the caller's record.
	r.Seq, r.PrevHash, r.RecordHash, r.CreatedAt = stored.Seq, prev, hash, stored.CreatedAt
	return nil
}

// Get returns a decrypted copy of the org's record, or ErrNotFound.
func (m *MemStore) Get(_ context.Context, orgID, decisionID string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.byOrg[orgID] {
		if ex.DecisionID == decisionID {
			out := *ex
			if err := decryptInto(m.enc, &out); err != nil {
				return nil, err
			}
			return &out, nil
		}
	}
	return nil, ErrNotFound
}

// List returns a filtered, paginated page (newest first) of decrypted copies.
func (m *MemStore) List(_ context.Context, orgID string, f Filter) (Page, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	limit := clampLimit(f.Limit)
	all := m.byOrg[orgID]

	// Newest first.
	idx := make([]*Record, len(all))
	copy(idx, all)
	sort.Slice(idx, func(i, j int) bool { return idx[i].Seq > idx[j].Seq })

	page := Page{Records: make([]*Record, 0, limit)}
	for _, ex := range idx {
		if f.Cursor > 0 && ex.Seq >= f.Cursor {
			continue
		}
		if !matches(ex, f) {
			continue
		}
		if len(page.Records) == limit {
			page.NextCursor = page.Records[len(page.Records)-1].Seq
			return page, nil
		}
		out := *ex
		if err := decryptInto(m.enc, &out); err != nil {
			return Page{}, err
		}
		page.Records = append(page.Records, &out)
	}
	return page, nil
}

// Mutate applies fn to the STORED record in place, bypassing append-only. It exists
// only to simulate an attacker with direct storage access in tamper tests; the real
// store has no such method and the DB trigger forbids UPDATE.
func (m *MemStore) Mutate(orgID, decisionID string, fn func(*Record)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.byOrg[orgID] {
		if ex.DecisionID == decisionID {
			fn(ex)
			return true
		}
	}
	return false
}

// matches applies the non-cursor filters (evaluated_at bounds use CreatedAt-parsed
// EvaluatedAt; for the mem store we compare the RFC 3339 string via time.Parse).
func matches(r *Record, f Filter) bool {
	if f.AgentID != "" && r.AgentID != f.AgentID {
		return false
	}
	if f.Verdict != "" && r.Verdict != f.Verdict {
		return false
	}
	if !f.From.IsZero() || !f.To.IsZero() {
		ts, err := time.Parse(time.RFC3339, r.EvaluatedAt)
		if err != nil {
			return false
		}
		if !f.From.IsZero() && ts.Before(f.From) {
			return false
		}
		if !f.To.IsZero() && !ts.Before(f.To) { // exclusive upper bound
			return false
		}
	}
	return true
}

// encryptInto encrypts the sensitive fields of r in place.
func encryptInto(enc Encryptor, r *Record) error {
	var err error
	if r.Amount, err = enc.Encrypt(r.Amount); err != nil {
		return err
	}
	if r.TargetType, err = enc.Encrypt(r.TargetType); err != nil {
		return err
	}
	if r.TargetID, err = enc.Encrypt(r.TargetID); err != nil {
		return err
	}
	return nil
}

// decryptInto decrypts the sensitive fields of r in place.
func decryptInto(enc Encryptor, r *Record) error {
	var err error
	if r.Amount, err = enc.Decrypt(r.Amount); err != nil {
		return err
	}
	if r.TargetType, err = enc.Decrypt(r.TargetType); err != nil {
		return err
	}
	if r.TargetID, err = enc.Decrypt(r.TargetID); err != nil {
		return err
	}
	return nil
}

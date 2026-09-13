package auth

import (
	"context"
	"sort"
	"time"
)

// KeyInfo is the non-secret, management-facing view of an API key (the dashboard's
// key list). It never contains key material — only the public id and metadata. It is
// deliberately separate from KeyRecord (the lean hot-path lookup shape) so adding
// management fields never widens the authentication read path.
type KeyInfo struct {
	KeyID     string     `json:"key_id"`
	OrgID     string     `json:"org_id"`
	Tier      string     `json:"tier"`
	Env       string     `json:"env"`
	Status    string     `json:"status"`
	Shadow    bool       `json:"shadow"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// KeyAdmin is the control-plane management seam for API keys: create, list, revoke.
// It is entirely separate from KeyStore (the hot-path lookup). Implementations:
// MemKeyStore (tests/local) and PostgresKeyStore (source of truth).
//
// CreateKey persists a freshly minted key's record (hash only — the raw key is never
// stored). ListKeys returns an org's keys, newest first. RevokeKey flips a key to
// revoked and returns its updated info; a revoked key still authenticates but is
// refused 403 (see Authenticate). Revocation should be paired with a cache eviction
// so "revoke = immediate" holds (TRD §11) — the HTTP layer wires that.
type KeyAdmin interface {
	CreateKey(ctx context.Context, rec KeyRecord, createdAt time.Time) error
	ListKeys(ctx context.Context, orgID string) ([]KeyInfo, error)
	RevokeKey(ctx context.Context, orgID, keyID string, at time.Time) (KeyInfo, error)
}

var (
	_ KeyAdmin = (*MemKeyStore)(nil)
	_ KeyAdmin = (*PostgresKeyStore)(nil)
)

// --- MemKeyStore admin implementation ---------------------------------------

// memInfo holds the management metadata MemKeyStore keeps alongside each KeyRecord.
type memInfo struct {
	createdAt time.Time
	revokedAt *time.Time
}

func (m *MemKeyStore) ensureInfo() {
	if m.info == nil {
		m.info = make(map[string]memInfo)
	}
}

// CreateKey inserts a new key so it authenticates immediately and appears in ListKeys.
func (m *MemKeyStore) CreateKey(_ context.Context, rec KeyRecord, createdAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureInfo()
	m.keys[rec.KeyID] = rec
	m.info[rec.KeyID] = memInfo{createdAt: createdAt}
	return nil
}

// ListKeys returns the org's keys, newest first.
func (m *MemKeyStore) ListKeys(_ context.Context, orgID string) ([]KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]KeyInfo, 0)
	for id, rec := range m.keys {
		if rec.OrgID != orgID {
			continue
		}
		out = append(out, m.infoOf(id, rec))
	}
	sortByCreatedDesc(out)
	return out, nil
}

// RevokeKey flips a key to revoked within its org. ErrKeyNotFound if none matches.
func (m *MemKeyStore) RevokeKey(_ context.Context, orgID, keyID string, at time.Time) (KeyInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ensureInfo()
	rec, ok := m.keys[keyID]
	if !ok || rec.OrgID != orgID {
		return KeyInfo{}, ErrKeyNotFound
	}
	rec.Status = StatusRevoked
	m.keys[keyID] = rec
	inf := m.info[keyID]
	revoked := at
	inf.revokedAt = &revoked
	m.info[keyID] = inf
	return m.infoOf(keyID, rec), nil
}

// infoOf composes a KeyInfo from a record and its stored metadata. Caller holds lock.
func (m *MemKeyStore) infoOf(id string, rec KeyRecord) KeyInfo {
	meta := m.info[id]
	return KeyInfo{
		KeyID:     rec.KeyID,
		OrgID:     rec.OrgID,
		Tier:      rec.Tier,
		Env:       rec.Env,
		Status:    rec.Status,
		Shadow:    rec.Shadow,
		CreatedAt: meta.createdAt,
		RevokedAt: meta.revokedAt,
	}
}

func sortByCreatedDesc(xs []KeyInfo) {
	sort.SliceStable(xs, func(i, j int) bool { return xs[i].CreatedAt.After(xs[j].CreatedAt) })
}

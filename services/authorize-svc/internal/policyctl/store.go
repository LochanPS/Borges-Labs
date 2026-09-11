package policyctl

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ErrPolicyNotFound / ErrVersionNotFound are returned when a lookup misses within the
// org scope. All reads are org-scoped: a caller only ever sees its own org's policies.
var (
	ErrPolicyNotFound  = errors.New("policyctl: policy not found")
	ErrVersionNotFound = errors.New("policyctl: version not found")
	ErrPolicyExists    = errors.New("policyctl: policy id already exists")
)

// Store persists the mutable policy working copies and the immutable, content-addressed
// version snapshots. Implementations: PostgresStore (source of truth) and MemStore (a
// hermetic in-memory fake for CI, same seam pattern as auth/ratelimit/audit).
//
// PutVersion is content-addressed and idempotent: re-putting an existing (org, policy,
// version_hash) is a no-op that reports created=false. This is what makes republishing
// identical content, and rollback (re-pointing at an existing hash), safe.
type Store interface {
	CreatePolicy(ctx context.Context, p *Policy) error
	GetPolicy(ctx context.Context, orgID, id string) (*Policy, error)
	UpdatePolicy(ctx context.Context, p *Policy) error

	PutVersion(ctx context.Context, v *Version) (created bool, err error)
	GetVersion(ctx context.Context, orgID, policyID, versionHash string) (*Version, error)
	ListVersions(ctx context.Context, orgID, policyID string) ([]*Version, error)
}

// Both stores satisfy Store.
var (
	_ Store = (*MemStore)(nil)
	_ Store = (*PostgresStore)(nil)
)

// MemStore is an in-memory Store for hermetic tests.
type MemStore struct {
	mu       sync.Mutex
	policies map[string]*Policy              // key: org|id
	versions map[string][]*Version           // key: org|policyID, insertion order
	seen     map[string]map[string]*Version  // key: org|policyID -> versionHash -> version
}

// NewMemStore builds an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		policies: make(map[string]*Policy),
		versions: make(map[string][]*Version),
		seen:     make(map[string]map[string]*Version),
	}
}

func key(org, id string) string { return org + "|" + id }

func (m *MemStore) CreatePolicy(_ context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(p.OrgID, p.ID)
	if _, ok := m.policies[k]; ok {
		return ErrPolicyExists
	}
	cp := *p
	m.policies[k] = &cp
	return nil
}

func (m *MemStore) GetPolicy(_ context.Context, orgID, id string) (*Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.policies[key(orgID, id)]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *MemStore) UpdatePolicy(_ context.Context, p *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(p.OrgID, p.ID)
	if _, ok := m.policies[k]; !ok {
		return ErrPolicyNotFound
	}
	cp := *p
	m.policies[k] = &cp
	return nil
}

func (m *MemStore) PutVersion(_ context.Context, v *Version) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(v.OrgID, v.PolicyID)
	if m.seen[k] == nil {
		m.seen[k] = make(map[string]*Version)
	}
	if _, ok := m.seen[k][v.VersionHash]; ok {
		return false, nil // content-addressed idempotent no-op
	}
	cp := *v
	m.seen[k][v.VersionHash] = &cp
	m.versions[k] = append(m.versions[k], &cp)
	return true, nil
}

func (m *MemStore) GetVersion(_ context.Context, orgID, policyID, versionHash string) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if vs, ok := m.seen[key(orgID, policyID)]; ok {
		if v, ok := vs[versionHash]; ok {
			cp := *v
			return &cp, nil
		}
	}
	return nil, ErrVersionNotFound
}

func (m *MemStore) ListVersions(_ context.Context, orgID, policyID string) ([]*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.versions[key(orgID, policyID)]
	out := make([]*Version, len(src))
	for i, v := range src {
		cp := *v
		out[i] = &cp
	}
	// Newest first (most recently published).
	sort.SliceStable(out, func(i, j int) bool { return out[i].PublishedAt.After(out[j].PublishedAt) })
	return out, nil
}

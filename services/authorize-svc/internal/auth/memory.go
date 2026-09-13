package auth

import (
	"context"
	"sync"
	"time"
)

// MemKeyStore is an in-memory KeyStore keyed by public key id. It is the fixture
// backing store for tests and a usable local-dev source; production uses Postgres.
type MemKeyStore struct {
	mu   sync.RWMutex
	keys map[string]KeyRecord
	info map[string]memInfo // management metadata (created_at/revoked_at) for KeyAdmin
}

// NewMemKeyStore builds a store seeded with the given records (indexed by KeyID).
func NewMemKeyStore(records ...KeyRecord) *MemKeyStore {
	m := &MemKeyStore{
		keys: make(map[string]KeyRecord, len(records)),
		info: make(map[string]memInfo, len(records)),
	}
	for _, r := range records {
		m.keys[r.KeyID] = r
		m.info[r.KeyID] = memInfo{createdAt: time.Now().UTC()}
	}
	return m
}

// Put inserts or replaces a record.
func (m *MemKeyStore) Put(r KeyRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[r.KeyID] = r
}

// LookupByID implements KeyStore.
func (m *MemKeyStore) LookupByID(_ context.Context, keyID string) (KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.keys[keyID]
	if !ok {
		return KeyRecord{}, ErrKeyNotFound
	}
	return r, nil
}

// MemNonceStore is an in-memory NonceStore with TTL expiry. Concurrency-safe so the
// replay tests can exercise it under parallel requests.
type MemNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time // composite key -> expiry
	now  func() time.Time
}

// NewMemNonceStore builds an empty nonce store.
func NewMemNonceStore() *MemNonceStore {
	return &MemNonceStore{seen: make(map[string]time.Time), now: time.Now}
}

// Remember implements NonceStore: it records (keyID, nonce) atomically and reports
// whether it was fresh. Expired entries are treated as absent.
func (m *MemNonceStore) Remember(_ context.Context, keyID, nonce string, ttl time.Duration) (bool, error) {
	k := keyID + "\x00" + nonce
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.seen[k]; ok && exp.After(now) {
		return false, nil
	}
	m.seen[k] = now.Add(ttl)
	return true, nil
}

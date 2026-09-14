package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// Chaos / fail-closed tests (TRD §21): when a backing store the authenticator depends
// on is unavailable, authentication must FAIL CLOSED — return an error, never a
// Principal. A check we cannot perform is a check that failed; letting the request
// through would be a silent authorization bypass.

type failingKeyStore struct{}

func (failingKeyStore) LookupByID(context.Context, string) (KeyRecord, error) {
	return KeyRecord{}, errors.New("postgres down")
}

type failingNonceStore struct{}

func (failingNonceStore) Remember(context.Context, string, string, time.Duration) (bool, error) {
	return false, errors.New("redis down")
}

type okNonceStore struct{}

func (okNonceStore) Remember(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func cfg() Config { return Config{MaxSkew: 5 * time.Minute, NonceTTL: 10 * time.Minute} }

func signedHeader(gk GeneratedKey, method, path string, body []byte) http.Header {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "nonce-abcdefgh"
	h := http.Header{}
	h.Set("Authorization", "Bearer "+gk.Plaintext)
	h.Set("X-Timestamp", ts)
	h.Set("X-Nonce", nonce)
	h.Set("X-Signature", Sign(gk.Plaintext, method, path, ts, nonce, body))
	return h
}

func TestChaos_KeyStoreDownFailsClosed(t *testing.T) {
	gk, _ := NewKey(EnvTest, "org1", "default")
	a := New(failingKeyStore{}, okNonceStore{}, cfg())

	body := []byte("{}")
	_, aerr := a.Authenticate(context.Background(), http.MethodPost, "/v1/authorize", signedHeader(gk, http.MethodPost, "/v1/authorize", body), body)
	if aerr == nil {
		t.Fatal("key store down but authentication succeeded — silent bypass")
	}
	if aerr.Status != http.StatusServiceUnavailable || aerr.Code != CodeUnavailable {
		t.Fatalf("got status=%d code=%s, want 503 %s", aerr.Status, aerr.Code, CodeUnavailable)
	}
}

func TestChaos_NonceStoreDownFailsClosed(t *testing.T) {
	// A fully valid, correctly-signed request must STILL be rejected when the replay
	// store cannot confirm the nonce is fresh (can't prove non-replay -> fail closed).
	gk, _ := NewKey(EnvTest, "org1", "default")
	store := NewMemKeyStore(gk.Record)
	a := New(store, failingNonceStore{}, cfg())

	body := []byte("{}")
	_, aerr := a.Authenticate(context.Background(), http.MethodPost, "/v1/authorize", signedHeader(gk, http.MethodPost, "/v1/authorize", body), body)
	if aerr == nil {
		t.Fatal("nonce store down but authentication succeeded — silent replay window")
	}
	if aerr.Status != http.StatusServiceUnavailable {
		t.Fatalf("got status=%d, want 503", aerr.Status)
	}
}

func TestChaos_HealthyStoresStillPass(t *testing.T) {
	// Sanity: the same request passes when both stores are healthy, proving the
	// fail-closed results above are caused by the store failures, not the fixture.
	gk, _ := NewKey(EnvTest, "org1", "default")
	a := New(NewMemKeyStore(gk.Record), okNonceStore{}, cfg())

	body := []byte("{}")
	p, aerr := a.Authenticate(context.Background(), http.MethodPost, "/v1/authorize", signedHeader(gk, http.MethodPost, "/v1/authorize", body), body)
	if aerr != nil {
		t.Fatalf("healthy path failed: %+v", aerr)
	}
	if p.OrgID != "org1" {
		t.Fatalf("principal org = %q, want org1", p.OrgID)
	}
}

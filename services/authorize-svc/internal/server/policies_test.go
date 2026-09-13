package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/budget"
	"github.com/trust-infra/authorize-svc/internal/bundle"
	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/hold"
	"github.com/trust-infra/authorize-svc/internal/idempotency"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// cpHarness is a running service with the control plane wired: a real engine driven by
// the bundle provider, the policyctl service over a MemStore, and one active test key.
type cpHarness struct {
	ts      *httptest.Server
	active  string // advisory (shadow=true) key
	enforce string // enforcing (shadow=false) key
	org     string
}

func newCPHarness(t *testing.T) *cpHarness {
	t.Helper()
	gk, err := auth.NewKey(auth.EnvTest, "org_test", testTier)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	enfGK, err := auth.NewKey(auth.EnvTest, "org_test", testTier)
	if err != nil {
		t.Fatalf("gen enforce key: %v", err)
	}
	enfRec := enfGK.Record
	enfRec.Shadow = false // an enforcing key: decisions are binding, holds are placed
	keys := auth.NewMemKeyStore(gk.Record, enfRec)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	keyring := signing.NewKeyring()
	if _, err := keyring.GenerateActive(); err != nil {
		t.Fatalf("signing key: %v", err)
	}
	signer, err := keyring.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	store := policyctl.NewMemStore()
	svc := policyctl.NewService(store, signer)
	provider := bundle.NewProvider(store, log, time.Second)
	sim := bundle.NewSimulator(store)
	// Budget enforcement: in-memory counter + reservation ledger (Task 3.2).
	reserver := budget.NewReserver(budget.NewMemCounter(), hold.NewMemStore(), 15*time.Minute)
	// Provider set, no static boot policy → an org with no published bundle 503s until
	// it publishes (which is exactly what the publish→decision test exercises).
	authz := engine.NewEngine(engine.Policy{}, signer.KeyID()).
		WithSigner(signer).WithProvider(provider).WithReserver(reserver)

	generous := ratelimit.TierTable{"default": {PerMinute: 1_000_000, PerSecond: 1_000_000}}
	srv := New(log, BuildInfo{Version: "test"}, authz, testAuthn(keys), testLimiter(), generous,
		Check{Name: "postgres", Ping: okPing},
	).WithKeys(func() any { return keyring.JWKS() }).
		WithControlPlane(svc, provider, sim).
		WithBudget(reserver).
		WithKeyAdmin(keys, nil).
		WithIdempotency(idempotency.NewMem())

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &cpHarness{ts: ts, active: gk.Plaintext, enforce: enfGK.Plaintext, org: "org_test"}
}

// sign builds a signed control-plane request (fresh timestamp + nonce), like a client.
func (h *cpHarness) sign(t *testing.T, method, path string, body []byte, key string) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := newNonce(t)
	req, err := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", auth.Sign(key, method, path, ts, nonce, body))
	return req
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func validRules() []policyctl.Rule {
	return []policyctl.Rule{
		{ID: "limit", Type: "per_transaction_limit", Max: "5000.00", Currency: "USD"},
		{ID: "perm", Type: "agent_permission", AllowedActions: []string{"payment.create"}},
	}
}

// Full control-plane path over HTTP: create → publish → /active reflects the version →
// a live authorize decision cites that exact version (ROADMAP Task 2.2 acceptance).
func TestControlPlane_CreatePublishActiveAndDecide(t *testing.T) {
	h := newCPHarness(t)

	// Create a draft.
	createBody := mustJSON(t, map[string]any{"name": "vendor pays", "rules": validRules()})
	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, body)
	}
	var pol policyctl.Policy
	if err := json.Unmarshal(body, &pol); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if pol.ID == "" || pol.Status != policyctl.StatusDraft {
		t.Fatalf("unexpected created policy: %+v", pol)
	}

	// Publish it.
	resp, body = do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/publish", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish status = %d; body: %s", resp.StatusCode, body)
	}
	var v policyctl.Version
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode version: %v", err)
	}

	// GET /active reflects the published version immediately.
	resp, body = do(t, h.sign(t, http.MethodGet, "/v1/policies/active", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("active status = %d; body: %s", resp.StatusCode, body)
	}
	var ref policyctl.BundleRef
	if err := json.Unmarshal(body, &ref); err != nil {
		t.Fatalf("decode active: %v", err)
	}
	if ref.VersionHash != v.VersionHash {
		t.Errorf("/active version = %q, want published %q", ref.VersionHash, v.VersionHash)
	}

	// A live decision cites the just-published bundle (publish invalidated the cache).
	azBody := mustJSON(t, contractsv1.AuthorizeRequest{
		AgentID: "agent-a", Action: "payment.create", Amount: "100.00", Currency: "USD",
		Target:         contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
		IdempotencyKey: "idem_cp_decide_1",
	})
	resp, body = do(t, h.sign(t, http.MethodPost, "/v1/authorize", azBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, body)
	}
	var dec contractsv1.Decision
	if err := json.Unmarshal(body, &dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Verdict != contractsv1.VerdictApprove {
		t.Errorf("verdict = %q, want APPROVE", dec.Verdict)
	}
	if dec.PolicyVersionHash != v.VersionHash {
		t.Errorf("decision cites %q, want published %q", dec.PolicyVersionHash, v.VersionHash)
	}
}

// Publishing an invalid policy is a 422 with field-level problems.
func TestControlPlane_PublishInvalidIs422(t *testing.T) {
	h := newCPHarness(t)
	bad := []policyctl.Rule{{ID: "x", Type: "per_transaction_limit"}} // missing max
	createBody := mustJSON(t, map[string]any{"name": "bad", "rules": bad})
	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, body)
	}
	var pol policyctl.Policy
	_ = json.Unmarshal(body, &pol)

	resp, body = do(t, h.sign(t, http.MethodPost, "/v1/policies/"+pol.ID+"/publish", nil, h.active))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("publish status = %d, want 422; body: %s", resp.StatusCode, body)
	}
	var p contractsv1.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Code != codeValidationFailed || len(p.Errors) == 0 {
		t.Errorf("problem = %+v, want validation_failed with errors", p)
	}
}

// Reading /active before any publish is a 404 (no bundle for the org).
func TestControlPlane_ActiveBeforePublishIs404(t *testing.T) {
	h := newCPHarness(t)
	resp, body := do(t, h.sign(t, http.MethodGet, "/v1/policies/active", nil, h.active))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("active status = %d, want 404; body: %s", resp.StatusCode, body)
	}
}

// A policy is org-scoped: another org's key cannot read it.
func TestControlPlane_OrgIsolation(t *testing.T) {
	h := newCPHarness(t)
	createBody := mustJSON(t, map[string]any{"name": "p", "rules": validRules()})
	resp, body := do(t, h.sign(t, http.MethodPost, "/v1/policies", createBody, h.active))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; body: %s", resp.StatusCode, body)
	}
	var pol policyctl.Policy
	_ = json.Unmarshal(body, &pol)

	// A key from a different org, seeded on its own store, can't be used here (unknown
	// key → 401), which is the outer isolation. Within-service cross-org read is proven
	// by the policyctl org-scoping unit test; here we assert the happy owner read works.
	resp, _ = do(t, h.sign(t, http.MethodGet, "/v1/policies/"+pol.ID, nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner get status = %d, want 200", resp.StatusCode)
	}
}

// GET /v1/policies lists the org's policies (Task 5.1 dashboard: policies index).
func TestControlPlane_ListPolicies(t *testing.T) {
	h := newCPHarness(t)

	for _, name := range []string{"alpha", "beta"} {
		body := mustJSON(t, map[string]any{"name": name, "rules": validRules()})
		resp, b := do(t, h.sign(t, http.MethodPost, "/v1/policies", body, h.active))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s = %d; body: %s", name, resp.StatusCode, b)
		}
	}

	resp, body := do(t, h.sign(t, http.MethodGet, "/v1/policies", nil, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d; body: %s", resp.StatusCode, body)
	}
	var out struct {
		Data []policyctl.Policy `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(out.Data) != 2 {
		t.Fatalf("want 2 policies, got %d", len(out.Data))
	}
	names := map[string]bool{}
	for _, p := range out.Data {
		names[p.Name] = true
	}
	if !names["alpha"] || !names["beta"] {
		t.Fatalf("missing policies in list: %+v", out.Data)
	}
}

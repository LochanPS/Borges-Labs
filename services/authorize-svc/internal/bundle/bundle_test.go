package bundle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// harness wires a MemStore + a real signer + a policyctl.Service so tests can publish
// versions the provider then reads.
type harness struct {
	store *policyctl.MemStore
	svc   *policyctl.Service
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	kr := signing.NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	store := policyctl.NewMemStore()
	var tick int64
	svc := policyctl.NewService(store, signer).
		WithClock(func() time.Time { tick++; return time.Unix(1_700_000_000+tick, 0).UTC() })
	return &harness{store: store, svc: svc}
}

func rules(maxAmount string) []policyctl.Rule {
	return []policyctl.Rule{
		{ID: "limit", Type: "per_transaction_limit", Max: maxAmount, Currency: "USD"},
		{ID: "perm", Type: "agent_permission", AllowedActions: []string{"payment.create"}},
		// A placeholder rule the local engine cannot evaluate — Compile must drop it.
		{ID: "budget", Type: "rolling_budget", Window: "month", Limit: "100000.00"},
	}
}

// publish creates + publishes a policy for org and returns the version hash.
func (h *harness) publish(t *testing.T, org, maxAmount string) string {
	t.Helper()
	p, err := h.svc.Create(context.Background(), org, "p", nil, rules(maxAmount))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	v, err := h.svc.Publish(context.Background(), org, p.ID, "tester")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	return v.VersionHash
}

func req(amount string) contractsv1.AuthorizeRequest {
	return contractsv1.AuthorizeRequest{
		AgentID: "agent-a", Action: "payment.create", Amount: amount, Currency: "USD",
		Target: contractsv1.Target{Type: contractsv1.TargetVendor, ID: "acme"},
	}
}

// Provider.Active compiles the active bundle, cites the published hash, and drops the
// enriched placeholder rule (only the 2 local predicates remain).
func TestProvider_ActiveCompilesAndCites(t *testing.T) {
	h := newHarness(t)
	hash := h.publish(t, "org1", "5000.00")

	p := NewProvider(h.store, nil, time.Second)
	pol, err := p.Active(context.Background(), "org1")
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if pol.Version != hash {
		t.Errorf("cited version = %q, want published %q", pol.Version, hash)
	}
	if len(pol.Predicates) != 2 {
		t.Errorf("compiled predicates = %d, want 2 (enriched dropped)", len(pol.Predicates))
	}
}

// An org with no published bundle yields ErrNoActiveBundle.
func TestProvider_NoBundle(t *testing.T) {
	h := newHarness(t)
	p := NewProvider(h.store, nil, time.Second)
	if _, err := p.Active(context.Background(), "ghost"); !errors.Is(err, ErrNoActiveBundle) {
		t.Errorf("Active(ghost) err = %v, want ErrNoActiveBundle", err)
	}
}

// A background refresh converges the cache to a version published after the first load.
func TestProvider_RefreshConverges(t *testing.T) {
	h := newHarness(t)
	v1 := h.publish(t, "org1", "5000.00")
	p := NewProvider(h.store, nil, time.Second)

	pol, _ := p.Active(context.Background(), "org1")
	if pol.Version != v1 {
		t.Fatalf("initial cite = %q, want v1", pol.Version)
	}

	// A new version is published (e.g. by another instance). Cache still holds v1...
	id := policyIDOf(t, h, "org1")
	if _, err := h.svc.Update(context.Background(), "org1", id, "", nil, rules("1000.00")); err != nil {
		t.Fatalf("update: %v", err)
	}
	v2ver, err := h.svc.Publish(context.Background(), "org1", id, "tester2")
	if err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	if cur, _ := p.Active(context.Background(), "org1"); cur.Version != v1 {
		t.Errorf("pre-refresh cite = %q, want still v1", cur.Version)
	}

	// ...until a refresh runs, after which the cache serves v2.
	p.refreshAll(context.Background())
	if cur, _ := p.Active(context.Background(), "org1"); cur.Version != v2ver.VersionHash {
		t.Errorf("post-refresh cite = %q, want v2 %q", cur.Version, v2ver.VersionHash)
	}
}

// A store error during refresh keeps the last-known-good bundle (never evicts it).
func TestProvider_LastKnownGoodOnError(t *testing.T) {
	h := newHarness(t)
	v1 := h.publish(t, "org1", "5000.00")

	fail := false
	src := &faultySource{store: h.store, fail: &fail}
	p := NewProvider(src, nil, time.Second)
	if pol, err := p.Active(context.Background(), "org1"); err != nil || pol.Version != v1 {
		t.Fatalf("warm load: pol=%v err=%v", pol.Version, err)
	}

	// Store starts failing; a refresh must NOT drop the cached bundle.
	fail = true
	p.refreshAll(context.Background())
	if pol, err := p.Active(context.Background(), "org1"); err != nil || pol.Version != v1 {
		t.Errorf("after store failure: pol=%v err=%v, want cached v1 still served", pol.Version, err)
	}
}

// End to end through the engine: a decision cites the org's active bundle; publish then
// rollback flip the served version, and each decision cites the version that decided it.
func TestEngine_ProviderDrivenDecisionAndRollback(t *testing.T) {
	h := newHarness(t)
	v1 := h.publish(t, "org1", "5000.00") // limit 5000
	p := NewProvider(h.store, nil, time.Second)
	eng := engine.NewEngine(engine.Policy{}, "test-key").WithProvider(p)
	ctx := context.Background()

	// $100 is within the v1 limit → APPROVE citing v1.
	d1, err := eng.Authorize(ctx, "org1", req("100.00"))
	if err != nil {
		t.Fatalf("authorize v1: %v", err)
	}
	if d1.Verdict != contractsv1.VerdictApprove || d1.PolicyVersionHash != v1 {
		t.Errorf("v1 decision = %s/%s, want APPROVE/%s", d1.Verdict, d1.PolicyVersionHash, v1)
	}

	// Tighten the limit to 50 and publish v2; invalidate for immediate convergence.
	id := policyIDOf(t, h, "org1")
	if _, err := h.svc.Update(ctx, "org1", id, "", nil, rules("50.00")); err != nil {
		t.Fatalf("update: %v", err)
	}
	v2, err := h.svc.Publish(ctx, "org1", id, "tester")
	if err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	if err := p.Invalidate(ctx, "org1"); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	d2, _ := eng.Authorize(ctx, "org1", req("100.00"))
	if d2.Verdict != contractsv1.VerdictDeny || d2.PolicyVersionHash != v2.VersionHash {
		t.Errorf("v2 decision = %s/%s, want DENY/%s", d2.Verdict, d2.PolicyVersionHash, v2.VersionHash)
	}

	// Roll back to v1; invalidate; the same $100 is APPROVED again citing v1.
	if _, err := h.svc.Rollback(ctx, "org1", id, v1); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := p.Invalidate(ctx, "org1"); err != nil {
		t.Fatalf("invalidate after rollback: %v", err)
	}
	d3, _ := eng.Authorize(ctx, "org1", req("100.00"))
	if d3.Verdict != contractsv1.VerdictApprove || d3.PolicyVersionHash != v1 {
		t.Errorf("post-rollback decision = %s/%s, want APPROVE/%s", d3.Verdict, d3.PolicyVersionHash, v1)
	}
}

// With a provider set but a static boot policy present, an org that has never published
// falls back to the static policy instead of failing.
func TestEngine_FallsBackToStaticWhenOrgHasNoBundle(t *testing.T) {
	h := newHarness(t)
	p := NewProvider(h.store, nil, time.Second)
	static := engine.Policy{
		Version:    "pol_static_boot",
		Predicates: []engine.Predicate{engine.NewPerTransactionLimit("lim", nil, "999999.00", "USD")},
	}
	eng := engine.NewEngine(static, "test-key").WithProvider(p)

	d, err := eng.Authorize(context.Background(), "orphan-org", req("100.00"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if d.PolicyVersionHash != "pol_static_boot" {
		t.Errorf("cited = %q, want static fallback pol_static_boot", d.PolicyVersionHash)
	}
}

// --- helpers -----------------------------------------------------------------

// policyIDOf returns the single policy id for an org (tests create exactly one).
func policyIDOf(t *testing.T, h *harness, org string) string {
	t.Helper()
	ref, err := h.store.GetActiveBundle(context.Background(), org)
	if err != nil {
		t.Fatalf("active bundle for %s: %v", org, err)
	}
	return ref.PolicyID
}

// faultySource wraps a MemStore and fails its two reads when *fail is set, to exercise
// last-known-good behavior.
type faultySource struct {
	store *policyctl.MemStore
	fail  *bool
}

var errBoom = errors.New("store down")

func (f *faultySource) GetActiveBundle(ctx context.Context, org string) (*policyctl.BundleRef, error) {
	if *f.fail {
		return nil, errBoom
	}
	return f.store.GetActiveBundle(ctx, org)
}

func (f *faultySource) GetVersion(ctx context.Context, org, policyID, hash string) (*policyctl.Version, error) {
	if *f.fail {
		return nil, errBoom
	}
	return f.store.GetVersion(ctx, org, policyID, hash)
}

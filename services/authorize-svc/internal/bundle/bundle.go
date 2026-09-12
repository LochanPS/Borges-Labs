// Package bundle is the decision plane's view of published policy: it compiles an
// immutable, signed control-plane version (policyctl.Version) into an evaluable
// engine.Policy and serves the active bundle per org from an in-memory cache
// (ROADMAP Task 2.2, A#4 "stale policy = wrong decision").
//
// Boundary rule (TRD §3). The hot path NEVER makes a synchronous call to the control
// plane. Provider.Active reads only the process-local cache. A background refresher
// (Provider.Run) re-reads each org's active version off the hot path and swaps the
// cached bundle when it changes; a same-process publish calls Invalidate for immediate
// convergence. If the store is unreachable on refresh, the last-known-good bundle keeps
// serving (§21) — decisions continue, policy edits merely pause. Only a cold miss (an
// org whose bundle has never been loaded) does a one-time bounded load; thereafter the
// path is pure cache.
//
// Even though Task 2.1 folded the control plane into this binary (A2#2), the cache +
// refresher model is deliberately the same one a separate policy-svc + sidecar would
// use, so splitting them out at Phase 5 changes wiring, not the decision path.
package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/trust-infra/authorize-svc/internal/engine"
	"github.com/trust-infra/authorize-svc/internal/policy"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// ErrNoActiveBundle is returned when an org has no published bundle to evaluate. It is
// engine.ErrNoActiveBundle so the engine can recognize it (to fall back to a static
// boot policy in file/GitOps mode, or surface a controlled 503 otherwise) without the
// engine importing this package.
var ErrNoActiveBundle = engine.ErrNoActiveBundle

// droppedTypes are the enrichment placeholder rule types the local engine cannot
// evaluate and that carry no Phase-3.1 meaning; Compile drops them from the servable
// bundle (enrichment adds them later). rolling_budget is NOT here — it is routed into
// Policy.Budgets so a decision can be marked budget-affecting (Phase 3.1).
var droppedTypes = map[string]bool{
	string(contractsv1.TypeSanctionsScreen): true,
	string(contractsv1.TypeVendorRisk):      true,
}

// Compile turns a published version into an evaluable engine.Policy. The cited
// Version is the published version_hash (polv_), so every decision references the exact
// signed control-plane version it was evaluated under. Enriched placeholder rules are
// dropped; the local subset is validated by the same loader the file path uses
// (internal/policy), which guarantees parity with what publish accepted.
func Compile(v *policyctl.Version) (engine.Policy, error) {
	return CompileRules(v.VersionHash, v.Rules)
}

// CompileRules compiles an arbitrary rule set under a version label into an
// engine.Policy. It is the shared core of Compile (published versions) and simulate
// (a draft working copy). Enriched placeholders are dropped; the local subset is
// validated by the decision plane's own loader (internal/policy) for parity.
func CompileRules(version string, rules []policyctl.Rule) (engine.Policy, error) {
	local := make([]policyctl.Rule, 0, len(rules))
	var budgets []engine.BudgetDecl
	for _, r := range rules {
		switch {
		case r.Type == string(contractsv1.TypeRollingBudget):
			budgets = append(budgets, engine.BudgetDecl{
				ID:       r.ID,
				Agents:   r.Agents,
				Window:   r.Window,
				Limit:    r.Limit,
				Currency: r.Currency,
			})
		case droppedTypes[r.Type]:
			// enrichment placeholder — not servable locally yet
		default:
			local = append(local, r)
		}
	}
	raw, err := json.Marshal(map[string]any{
		"version":    version,
		"predicates": local,
	})
	if err != nil {
		return engine.Policy{}, fmt.Errorf("bundle: marshal for compile: %w", err)
	}
	pol, err := policy.Parse(raw)
	if err != nil {
		return engine.Policy{}, fmt.Errorf("bundle: compile %s: %w", version, err)
	}
	pol.Budgets = budgets
	return pol, nil
}

// Source is the read side of the control-plane store the provider needs. Satisfied by
// *policyctl.PostgresStore and *policyctl.MemStore.
type Source interface {
	GetActiveBundle(ctx context.Context, orgID string) (*policyctl.BundleRef, error)
	GetVersion(ctx context.Context, orgID, policyID, versionHash string) (*policyctl.Version, error)
}

// entry is a cached compiled bundle plus the version hash it was compiled from.
type entry struct {
	hash string
	pol  engine.Policy
}

// Provider serves and refreshes per-org active bundles from an in-memory cache.
type Provider struct {
	src         Source
	log         *slog.Logger
	loadTimeout time.Duration

	mu    sync.RWMutex
	cache map[string]entry // orgID -> compiled bundle
}

// NewProvider builds a provider over the control-plane store. loadTimeout bounds a
// cold-miss load so a slow store cannot stall the first request indefinitely.
func NewProvider(src Source, log *slog.Logger, loadTimeout time.Duration) *Provider {
	if loadTimeout <= 0 {
		loadTimeout = 2 * time.Second
	}
	return &Provider{src: src, log: log, loadTimeout: loadTimeout, cache: make(map[string]entry)}
}

// Active returns the org's cached bundle. On a cold miss it does a single bounded load
// and caches the result; every subsequent call is pure cache (no I/O on the hot path).
// Returns ErrNoActiveBundle if the org has never published.
func (p *Provider) Active(ctx context.Context, orgID string) (engine.Policy, error) {
	p.mu.RLock()
	e, ok := p.cache[orgID]
	p.mu.RUnlock()
	if ok {
		return e.pol, nil
	}
	return p.load(ctx, orgID)
}

// load fetches, compiles, and caches the org's active bundle. It is used for the cold
// miss and by Invalidate; the refresher uses refreshOrg instead (which keeps the old
// bundle on error).
func (p *Provider) load(ctx context.Context, orgID string) (engine.Policy, error) {
	ctx, cancel := context.WithTimeout(ctx, p.loadTimeout)
	defer cancel()

	ref, err := p.src.GetActiveBundle(ctx, orgID)
	if errors.Is(err, policyctl.ErrBundleNotFound) {
		return engine.Policy{}, ErrNoActiveBundle
	}
	if err != nil {
		return engine.Policy{}, fmt.Errorf("bundle: read active for org %s: %w", orgID, err)
	}
	pol, err := p.compileRef(ctx, ref)
	if err != nil {
		return engine.Policy{}, err
	}
	p.store(orgID, entry{hash: ref.VersionHash, pol: pol})
	return pol, nil
}

func (p *Provider) compileRef(ctx context.Context, ref *policyctl.BundleRef) (engine.Policy, error) {
	v, err := p.src.GetVersion(ctx, ref.OrgID, ref.PolicyID, ref.VersionHash)
	if err != nil {
		return engine.Policy{}, fmt.Errorf("bundle: load version %s: %w", ref.VersionHash, err)
	}
	return Compile(v)
}

func (p *Provider) store(orgID string, e entry) {
	p.mu.Lock()
	p.cache[orgID] = e
	p.mu.Unlock()
}

// Invalidate forces an immediate reload of an org's bundle (called after a same-process
// publish/rollback for instant convergence). A failure is returned for the caller to
// log; the previously cached bundle is left in place on error.
func (p *Provider) Invalidate(ctx context.Context, orgID string) error {
	_, err := p.load(ctx, orgID)
	return err
}

// Run refreshes every cached org's bundle on an interval until ctx is cancelled. It is
// the cross-instance convergence mechanism: an org whose active version changed
// elsewhere converges here within one interval. A store error on refresh keeps the
// last-known-good bundle (§21) — it never evicts a working bundle.
func (p *Provider) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.refreshAll(ctx)
		}
	}
}

func (p *Provider) refreshAll(ctx context.Context) {
	p.mu.RLock()
	orgs := make([]string, 0, len(p.cache))
	for org := range p.cache {
		orgs = append(orgs, org)
	}
	p.mu.RUnlock()

	for _, org := range orgs {
		p.refreshOrg(ctx, org)
	}
}

// refreshOrg re-reads one org's active version and recompiles only if the hash changed.
// On any error it logs and returns, leaving the cached bundle untouched.
func (p *Provider) refreshOrg(ctx context.Context, orgID string) {
	rctx, cancel := context.WithTimeout(ctx, p.loadTimeout)
	defer cancel()

	ref, err := p.src.GetActiveBundle(rctx, orgID)
	if err != nil {
		if p.log != nil && !errors.Is(err, policyctl.ErrBundleNotFound) {
			p.log.Warn("bundle refresh: read active failed; keeping last-known-good", "org", orgID, "err", err)
		}
		return
	}

	p.mu.RLock()
	cur, ok := p.cache[orgID]
	p.mu.RUnlock()
	if ok && cur.hash == ref.VersionHash {
		return // unchanged
	}

	pol, err := p.compileRef(rctx, ref)
	if err != nil {
		if p.log != nil {
			p.log.Warn("bundle refresh: compile failed; keeping last-known-good", "org", orgID, "err", err)
		}
		return
	}
	p.store(orgID, entry{hash: ref.VersionHash, pol: pol})
	if p.log != nil {
		p.log.Info("bundle refreshed", "org", orgID, "version", ref.VersionHash)
	}
}

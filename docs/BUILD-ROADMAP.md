# Build Roadmap — step-by-step prompts to finish the product

A build-ready plan from today's state (MVP complete; M1 onboarding/RBAC partly done) to
a full-scale product. **Each step is a self-contained prompt** you can hand to a coding
agent or engineer. Steps are ordered; finish one, commit, move on.

Companion docs: [PRODUCT-STATUS-AND-ROADMAP.md](PRODUCT-STATUS-AND-ROADMAP.md) (the audit
+ backlog), [ROADMAP.md](../ROADMAP.md) (Phases 0–6), [TRD.md](../TRD.md), [PRD.md](../PRD.md).

---

## How to use this

Every prompt assumes these **conventions** (paste the relevant ones into the prompt if
your agent starts cold):

```
Repo: C:\Users\pokka\trust infra
- Go decision/control plane: services/authorize-svc (Go 1.23). Format with the 1.23
  toolchain: `GOTOOLCHAIN=go1.23.0 gofmt -w <files>`; test: `go test ./...`.
- Contracts (source of truth): contracts/ — OpenAPI 3.1 + JSON Schema. After a change
  run `python contracts/tools/validate.py`; regenerate TS types `node contracts/tools/gen-ts.mjs`.
- SDKs: sdks/python (pytest), sdks/ts (npm test/build).
- Dashboard: services/dashboard (Next.js 15 App Router, Tailwind v4, optional Clerk).
- Whole-repo tests: `make test-all` (or `./tasks.ps1 test-all`).
- Never commit secrets. End commits with:
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

**Definition of done for every step:** code + tests written; `make test-all` green;
gofmt/type-check clean; contract validates if touched; docs updated; one focused commit.

**Status legend:** ✅ done · �builds-on prior step · ⬜ not started.

---

## Milestone status snapshot

- ✅ Phases 0–6 core (contracts, decision plane, policy/shadow, budgets, SDKs, docs,
  dashboard, observability, deploy configs).
- ✅ M1a: org provisioning endpoint (`POST /v1/provision/keys`), dashboard RBAC, connect-
  your-agent wizard, free demo agent, in-UI playground.
- ⬜ **M1b** (below) → M2 → M3 → M4 → M5 → M6 → Enterprise.

---

# M1b — Multi-tenant per-org keys (finish onboarding)

Goal: each dashboard user acts inside their own org, and the dashboard calls authorize-svc
with **that org's** key (auto-provisioned), not one shared admin key.

### Step M1b.1 — Encrypted org-key store (dashboard) ⬜

```
In services/dashboard, add a per-org API-key store used server-side only.

1. src/lib/crypto.ts: AES-256-GCM encrypt/decrypt helpers using a key from env
   DASHBOARD_ENC_KEY (base64/hex 32 bytes). Export encryptSecret(plain): string
   ("v1.<iv>.<ct>.<tag>" base64url parts) and decryptSecret(blob): string. If
   DASHBOARD_ENC_KEY is unset, throw a clear error at first use (never store plaintext).
2. src/lib/org-keys.ts: interface OrgKeyStore { get(orgId): Promise<string|null>;
   set(orgId, secret): Promise<void> } storing the ENCRYPTED secret. Provide:
   - MemoryOrgKeyStore (module singleton Map) — the default, works locally.
   - PostgresOrgKeyStore (optional, gated on DATABASE_URL) — a table
     org_admin_keys(org_id text primary key, enc_secret text, created_at timestamptz);
     use a minimal pg client (add `pg` dep) but keep it lazy so mem path needs no dep.
   Export orgKeyStore() that returns Postgres when DATABASE_URL set, else Memory.
3. Unit tests (test/org-keys.test.ts via `node --import tsx --test`): crypto round-trip;
   set/get returns the plaintext; get(unknown)=null; stored value is not the plaintext.

Acceptance: npm test passes; secrets are encrypted at rest; no plaintext in the store.
```

### Step M1b.2 — Auto-provision + route API calls per-org ⬜

```
Wire the dashboard to obtain and use the current org's key.

1. src/lib/config.ts: add provisionToken (AUTHZ_PROVISION_TOKEN), encKey
   (DASHBOARD_ENC_KEY); add provisioningEnabled() = baseUrl && provisionToken.
2. src/lib/provisioning.ts: provisionOrgKey(orgId) POSTs /v1/provision/keys with header
   X-Provision-Token (raw fetch, NOT HMAC-signed) → returns the created secret.
   resolveOrgKey(orgId): return decrypt(store.get) or, on miss, provisionOrgKey → encrypt
   + store → return. Concurrency-safe (single-flight per orgId).
3. src/lib/api.ts: in call(), choose the signing key: when provisioningEnabled(), resolve
   the caller's org key via currentIdentity().orgId → resolveOrgKey(orgId); else fall back
   to config.apiKey (single-tenant/dev). Mock mode is unchanged.
4. Tests: resolveOrgKey provisions exactly once then caches (fake provisioner + memory
   store); api.call uses the resolved key (assert the X-Api-Key header).

Acceptance: with provisioning configured, two different orgs get two different keys, each
scoped to its own org; without it, behavior is unchanged. make test-all green.
```

### Step M1b.3 — Clerk Organizations wiring ⬜

```
Make identity real when Clerk is configured (services/dashboard).

1. Require Clerk org context: middleware redirects a signed-in user with no active org to
   an org-create/switch screen (Clerk <OrganizationSwitcher/> / createOrganization).
2. On first use of an org, ensure an authorize-svc org exists by calling resolveOrgKey
   (M1b.2) with a STABLE org id derived from the Clerk org id (e.g. "org_"+clerkOrgId).
   Map lib/identity.ts orgId to that stable id in the Clerk branch.
3. Role mapping: Clerk org role -> owner/admin/developer/viewer (admin => admin, member =>
   developer; treat the creator as owner). Keep the dev-cookie fallback.
4. Docs: dashboard README + DEPLOY.md — set NEXT_PUBLIC_CLERK_* + CLERK_SECRET_KEY,
   AUTHZ_PROVISION_TOKEN (matching the service), DASHBOARD_ENC_KEY, DATABASE_URL.

Acceptance (manual, needs Clerk keys): a brand-new Clerk org can sign up, gets its own
provisioned key on first control-plane call, and RBAC follows the Clerk role. Dev-bypass
still works with the role switcher.
```

### Step M1b.4 — authorize-svc: audit of control-plane actions ⬜

```
Add a control-plane action audit trail (who changed what) — needed for multi-tenant trust.

In services/authorize-svc: on policy publish/rollback and key create/revoke, append an
event {org_id, actor_key_id, action, target, at} to a new append-only table
cp_audit (migration 0007) via a small ControlPlaneAudit writer (mirror internal/audit
patterns; async, never blocks). Expose GET /v1/control-audit (org-scoped, paginated) +
contract + tests. Dashboard: a read-only "Activity" tab on the org settings page.

Acceptance: publishing a policy and revoking a key produce audit rows retrievable via the
endpoint; go test ./... green; contract validates.
```

---

# M2 — Agent management + usage metering

Goal: agents are first-class (registry + per-agent enforce), and orgs see their usage.

### Step M2.1 — Agent registry (contract + service) ⬜

```
Add agents as managed objects (data model already has principals/agents).

1. contracts: add /v1/agents — POST (create {id,name,principal?}), GET (list),
   GET/PATCH /v1/agents/{id} (incl. an `enforce` boolean). Add an Agent schema. Validate +
   gen-ts.
2. services/authorize-svc: internal/agentctl (Service + Store: Mem + Postgres), migration
   0008_agents (org_id, id, name, principal, enforce bool default false, timestamps).
   Handlers org-scoped + admin-gated (reuse the auth scopes plan below). Tests.
3. sdks: optional agents() helpers (list/get) in python + ts.

Acceptance: create/list/get/patch an agent; org isolation enforced; go test ./... green.
```

### Step M2.2 — Per-agent enforce (engine) ⬜

```
Let enforcement be decided per agent, not only per key.

In services/authorize-svc engine: when evaluating, resolve the agent's `enforce` flag
(from agentctl, via the bundle/cache off the hot path) and set decision.shadow =
!(agentEnforce) UNLESS the key is already shadow (key-shadow still wins as the safety
default). Document precedence in code + docs/running-locally.md. Add engine tests:
agent enforce=false => shadow decision even on an enforcing key; enforce=true + enforcing
key => enforceable.

Acceptance: the shadow->enforce lever works per agent; existing key-shadow tests still pass.
```

### Step M2.3 — Usage metering endpoint + dashboard ⬜

```
Surface decisions/month per org and per agent (data is already in the audit store).

1. services/authorize-svc: GET /v1/usage?from=&to=&group_by=agent|day returning counts
   (total + verdict breakdown) from the decisions store; org-scoped; contract + tests.
2. dashboard: a Usage view (charts: decisions/day, verdict mix, top agents) using the
   dataviz guidance; add to Overview or a /usage page.

Acceptance: usage numbers match the audit rows; charts render in light+dark.
```

### Step M2.4 — Upgrade /agents dashboard page ⬜

```
Turn the derived /agents page (services/dashboard/src/app/agents) into a management view:
list registered agents (M2.1), per-agent verdict mix + spend (M2.3), and an enforce toggle
(admin-only) that PATCHes /v1/agents/{id}. Link each to its audit trail.

Acceptance: an admin flips an agent shadow->enforce from the UI and the next decision for
that agent is enforceable; viewers see read-only.
```

---

# M3 — REVIEW approval queue (human-in-the-loop)

Goal: a REVIEW verdict lands in a queue a human clears; approval releases the action.

### Step M3.1 — Reviews store + endpoints ⬜

```
contracts: add Review {id, decision_id, org_id, status(pending|approved|denied), reason?,
created_at, resolved_at, resolver?}. Endpoints: GET /v1/reviews?status=, POST
/v1/reviews/{id}/approve, POST /v1/reviews/{id}/deny. Validate + gen-ts.

services/authorize-svc: internal/reviewctl (Service + Mem/Postgres store, migration 0009).
When a decision resolves to REVIEW (and the key/agent enforces), create a pending review
row. approve/deny endpoints (org-scoped, admin-gated) transition it. Tests.

Acceptance: a REVIEW decision creates a pending review; approve/deny transitions it; org
isolation holds; go test ./... green.
```

### Step M3.2 — Obligation + resolution semantics ⬜

```
Wire REVIEW into the decision obligations and a resolution read path.

- The REVIEW decision carries an obligation {type:"human_review_required", params:{review_id}}.
- Add GET /v1/decisions/{id} to include review status when present.
- SDK: Decision.review_required helper; a poll/callback pattern doc for how a caller waits
  for approval (or treats REVIEW as DENY if it can't wait). Update sdks/python + sdks/ts +
  their READMEs. Tests.

Acceptance: SDK exposes the review obligation; docs explain the wait/deny pattern.
```

### Step M3.3 — Dashboard approvals queue ⬜

```
dashboard: /reviews page — a queue of pending reviews (decision summary, amount, agent,
matched rules) with Approve/Deny buttons (admin-only, server actions calling the endpoints)
and a reason field. Badge the nav with the pending count. Link each row to the receipt.

Acceptance: a reviewer clears a pending review from the UI; the queue count updates.
```

---

# M4 — Reliability & ops

### Step M4.1 — Prometheus alert rules ⬜

```
Add deploy/prometheus/alerts.yml with rules over the /metrics series:
- latency SLO burn (authz_decision_latency_ms p95 over target for N minutes),
- rate-limit spike (rate(authz_rate_limited_total)),
- deny-rate anomaly, and a scrape-up alert.
Add deploy/prometheus/README.md wiring a scrape config + Alertmanager. No code change to
the service. Validate YAML in CI (a small promtool step or yaml lint).

Acceptance: promtool check passes; alerts documented.
```

### Step M4.2 — Sentry error tracking ⬜

```
services/authorize-svc: optional Sentry (getsentry/sentry-go) initialized only when
SENTRY_DSN is set; capture panics (in recoverPanic) and 5xx internal errors; scrub PII
(never send amounts/targets/keys). dashboard: @sentry/nextjs gated on NEXT_PUBLIC_SENTRY_DSN.
Docs + env. Tests: Sentry-disabled path is a no-op (default).

Acceptance: with DSN unset nothing changes and tests pass; with DSN set, a forced panic is
captured (manual).
```

### Step M4.3 — Public status page ⬜

```
A standalone public status page (docs-site or a tiny static page) polling a PUBLIC health
summary. Add GET /v1/status (unauth, cacheable) returning {status, enrichment, incidents?}
WITHOUT internal detail. Page shows component health + 90-day uptime placeholder. Deploy
note. Keep it separate from the authenticated dashboard /status.

Acceptance: /v1/status returns non-sensitive health; the page renders it and auto-refreshes.
```

### Step M4.4 — k6 load test + SLO gate ⬜

```
Add loadtest/ with a k6 script driving POST /v1/authorize (signed like the SDK) at a target
RPS, asserting p95 < the TRD §5 target and error-rate ~0. A Makefile target `loadtest`
(needs a running service + a key). Document how to run against a deploy. Optional CI job
(manual trigger) that runs a short smoke load against the compose stack.

Acceptance: k6 runs, prints p50/p95/p99 + error rate, fails if p95 exceeds the target.
```

---

# M5 — Enrichment pack (optional predicates)

### Step M5.1 — Enriched predicate framework ⬜

```
services/authorize-svc engine: an EnrichedPredicate seam — timeout-bounded, concurrent,
with a declared fail-mode (fail_open|fail_closed) per predicate that governs the combined
verdict when the predicate returns UNAVAILABLE (never a fabricated SATISFIED; TRD §21).
Add engine tests for timeout -> UNAVAILABLE -> declared fail-mode; concurrency; and that a
local hard DENY still short-circuits before enrichment.

Acceptance: enrichment can time out and the verdict follows the declared fail policy;
determinism of local predicates is unaffected.
```

### Step M5.2 — sanctions_screen + vendor_risk predicates ⬜

```
Implement the two placeholder predicate types (contracts already list them). Each calls an
adapter interface (pluggable; a stub/local adapter for tests + a real HTTP adapter behind
env). Wire into the policy schema/engine as enriched predicates using M5.1. Contract:
document their params. Tests with the stub adapter (hit/no-hit, timeout, error).

Acceptance: a policy using sanctions_screen/vendor_risk evaluates deterministically with
the stub; real adapter is config-gated.
```

### Step M5.3 — ComplianceAPI policy pack template ⬜

```
Ship a ready-made policy pack (sanctions + spend + jurisdiction) as a JSON template under
policy-packs/complianceapi/ plus a one-command import (a CLI or a dashboard "install pack"
that creates+publishes it). Doc a day-one walkthrough. This is the GTM wedge (PRD §9).

Acceptance: a new org installs the pack and gets a working sanctions+spend policy without
authoring rules by hand.
```

---

# M6 — Billing & developer experience

### Step M6.1 — Usage export + Stripe metered billing ⬜

```
Add GET /v1/usage/export (NDJSON/CSV, org-scoped, date-ranged). dashboard: a Billing page
showing current-period decisions + tier. Integrate Stripe metered billing (report
decisions/day to a Stripe meter) behind STRIPE_* env; tiers Free/Team/Enterprise (PRD §8).
Keep it off by default (invoice manually until ~5 paying customers). Webhook to sync
subscription state. Tests for the meter reporter (fake Stripe).

Acceptance: usage exports match the audit store; with Stripe configured, decisions report
to the meter; disabled by default.
```

### Step M6.2 — Webhooks ⬜

```
Outbound webhooks on events: decision.denied, decision.review, budget.threshold,
key.created, key.revoked, enrichment.degraded. contracts: WebhookEndpoint + event
schemas. services/authorize-svc: endpoints to register/list/delete endpoints (org-scoped,
admin-gated, migration), an async signed-delivery worker (Ed25519 signature over the
payload, reuse the signer), retries with backoff + dead-letter. Tests: delivery, signature,
retry. dashboard: a Webhooks settings page.

Acceptance: a registered endpoint receives a signed decision.denied payload; failures retry
then dead-letter; org isolation holds.
```

### Step M6.3 — Go SDK ⬜

```
sdks/go: mirror the Python/TS SDK surface (Authorize/Shadow/Capture/Void/VerifyDecision),
HMAC azn-hmac/1 signing, Ed25519 decision verification, on_unavailable fail modes, typed
errors (RFC 7807). Reuse contracts/gen/go types. Table tests incl. a real signed-decision
verify + fail-mode tests. README + example. Add to CI + Makefile.

Acceptance: `go test ./...` in sdks/go green; a 3-line example authorizes+enforces; never a
silent APPROVE.
```

### Step M6.4 — Java SDK ⬜

```
sdks/java (Maven/Gradle): same surface as above. Types generated from /contracts (add a
Java target to a generator or use openapi-generator). BouncyCastle/JCA for Ed25519 verify;
HMAC-SHA256 signing. JUnit tests (signed-decision verify, fail modes). README + example.

Acceptance: mvn test green; 3-line example works; verify validates a real signed decision.
```

### Step M6.5 — CLI (azn) ⬜

```
A cross-platform CLI `azn` (Go, reusing the Go SDK from M6.3): `azn keys create|list|revoke`,
`azn authorize -f txn.json`, `azn simulate`, `azn decisions tail`, `azn verify receipt.json`.
Config via env/flags (base url, key). Ship binaries in CI releases. Docs.

Acceptance: each subcommand works against a running service; `azn verify` validates a
receipt offline.
```

### Step M6.6 — Audit export + decision search + guided policy builder ⬜

```
dashboard: (a) audit export (CSV/NDJSON) button on /audit; (b) richer decision search
(verdict, agent, date, amount range, text) backed by query params on /v1/decisions (extend
the contract + service filters + tests); (c) a guided policy rule builder (forms per
predicate type) that emits the rules JSON the editor already accepts — no raw JSON needed
for the 6 local predicates.

Acceptance: non-engineers can build+publish a policy without writing JSON; audit exports
download; search filters work end to end.
```

---

# Enterprise (P2 — pull-driven)

Each is a milestone; prompt-per-step when you pick it up.

- **SSO/SAML + SCIM** ⬜ — enterprise IdP login + user provisioning (Clerk enterprise or
  WorkOS); map IdP groups → roles; enforce at the dashboard + a machine-token path for the
  API.
- **Self-host / VPC** ⬜ — Helm chart + Docker images for authorize-svc + control plane in
  a customer VPC; same bundle format; docs for air-gapped signing-key custody (KMS/HSM).
- **Sidecar / edge evaluation** ⬜ (TRD §8) — a sidecar that evaluates local predicates
  in-process for sub-ms decisions, syncing signed bundles from the control plane; falls
  back to the hosted plane for enriched predicates.
- **Policy analyzer** ⬜ — static analysis proving properties (e.g. "can never approve >
  $X", "policies A and B don't contradict"); surfaced in the dashboard before publish.
- **Multi-agent / delegated authority chains** ⬜ — an agent acting on behalf of another;
  delegation tokens + chain verification in the decision + explanation.
- **Policy-pack marketplace** ⬜ — publish/install shareable signed policy packs.
- **SOC 2 Type II + data residency** ⬜ — controls, evidence collection, regional
  deployments; DPA.

---

## Suggested order & why

1. **M1b** — makes onboarding truly multi-tenant (the thing blocking hands-off design
   partners). Small, high leverage.
2. **M2** — agent management + usage: what an operator wants once real traffic flows, and
   the per-agent enforce lever is the core rollout control.
3. **M3** — REVIEW queue: closes the last MVP-adjacent gap (human-in-the-loop).
4. **M4** — reliability/ops: needed before leaning on the system in production.
5. **M5** — enrichment pack: the ComplianceAPI GTM wedge.
6. **M6** — billing + DX breadth once there's demand.
7. **Enterprise** — as customers pull for it.

Track each step as a checkbox here; flip ⬜ → ✅ as you land its commit.

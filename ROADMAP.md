# Build Roadmap — AI Transaction Authorization Infrastructure

*Companion to [PRD.md](PRD.md) + [TRD.md](TRD.md). This is the execution doc: phases → tasks → **paste-ready prompts** for fresh build sessions. Each prompt is self-contained (a new session has zero context), names the deliverable, the constraints, and the acceptance criteria.*

*How to use: open a new session in this repo, paste one prompt, build, verify against its acceptance criteria, commit. Move to the next. Do them in order — later prompts assume earlier deliverables exist.*

---

## A. Critical Review — Weak Spots Found & Better Decisions (read before building)

I re-examined PRD/TRD cold. Genuine problems and upgrades, in priority order. **These supersede the earlier docs where they conflict; the prompts below already bake them in.**

1. **[SECURITY BUG] Decision signatures must be asymmetric, not HMAC.** TRD §11 conflated two signatures. Request auth (customer→us) = HMAC (symmetric) is fine. But the **decision receipt** must be verifiable by the customer *and* third parties (auditors, regulators) without holding a secret they could forge with. Use **Ed25519**: we sign decisions with a private key in KMS; we publish the public key; anyone verifies. HMAC here would let any key-holder forge our decisions — unacceptable for an audit artifact. *Fixed in TRD §11 and prompt 1.5.*

2. **[DESIGN GAP] Authorize is not a pure read — it needs authorize/capture two-phase.** If a decision decrements a budget, then `/authorize` has a side effect, and an APPROVE followed by a *failed* downstream payment leaves budget consumed for money that never moved. This is the classic card **auth vs capture** problem. Decision: `POST /v1/authorize` **evaluates + optionally places a hold** (reservation) but does not commit; `POST /v1/authorize/{id}/capture` commits the budget after the payment succeeds; `POST /v1/authorize/{id}/void` releases the hold. Holds auto-expire (TTL). Without this, budgets drift and double-count on retries. *Added to TRD §9; built in Phase 3.*

3. **[REFINEMENT] Cedar fits permissions, not aggregates.** Cedar (recommended for Prod) is built for principal/action/resource/context authorization and *deliberately* avoids arbitrary computation and external-data joins (that's why it's analyzable). "Sum of spend this month < limit" does **not** live in Cedar. Correct split: **permission predicates** (may agent X pay vendor Z) → Cedar/engine; **stateful/aggregate predicates** (budgets, velocity) → a separate accumulator service that computes a boolean and injects it into the decision context. Don't try to express budgets in Cedar. *Refines TRD §6.*

4. **[GAP] Policy-bundle propagation is unspecified — stale policy = wrong decision.** Inline nodes cache bundles; a publish must propagate deterministically. Design: publish writes a new immutable version + hash; decision nodes hold `active_version` and pull/subscribe; each decision records the exact `policy_version_hash` it used; a publish is "live" only when all nodes confirm the new version (or after a bounded convergence window). Add a `GET /v1/policies/active` so a customer can see which version is serving. *Built in prompt 2.2.*

5. **[POSITIONING/LEGAL] Advisory vs authoritative is a real liability fork, not a footnote.** "Payment never reaches the processor on DENY" = you are in the enforcing path = heavier liability (a wrong DENY blocks legit revenue; a wrong APPROVE is in the causal chain). Recommendation: **default advisory + shadow at first** (you inform, customer's code decides), move to **enforcing** only with explicit opt-in and contractual limitation-of-liability. Get a lawyer's read before any customer runs enforce-mode in production. *Reflected in PRD §11 open questions; make it a contract term, not just code.*

6. **[TRIM] Don't build a "policy compiler" at MVP.** For 6 JSON predicate types, "compile" = validate + version + content-hash + sign the JSON. Calling it a compiler invites a pipeline you don't need yet. Keep it dumb until Cedar. *Simplifies TRD §6 for MVP.*

7. **[DETERMINISM precision] Determinism is over the full input vector including injected time + counter snapshot.** Time-of-day and budget-window predicates are time-dependent, so the evaluation `timestamp` and the `counter_state` are **explicit inputs** injected by the orchestrator, never read via wall-clock/network inside a predicate. Then "same input ⇒ same output" holds literally and decisions are replayable. *Tighten in prompt 1.4.*

8. **[DX alternative worth offering] Policy-as-files (GitOps), not only dashboard.** Infra buyers often want policy in *their* git, PR-reviewed. Offer a file format the control plane can sync from a repo, in addition to dashboard authoring. Cheap to support if policy is already declarative JSON. *Optional, Phase 5+.*

9. **[COMMERCIAL risk] Per-decision pricing can discourage calling you** (skip the call, save money, create coverage gaps that erode your value). Price low enough that "always call" is a no-brainer, or bundle generously with a floor. *Note in pricing.*

10. **[PII tension] Audit needs the data; minimization wants it gone.** Resolve with field-level encryption on sensitive fields + configurable retention per tier, not by dropping audit fields. *Built into data model in prompt 1.6.*

**Net:** the two that change code you'd otherwise write wrong are **#1 (Ed25519 decisions)** and **#2 (authorize/capture)**. Everything else is refinement or positioning.

---

## A2. Plan amendments — de-scope & managed swaps (2026-08-31)

Reviewed the plan after building through Task 1.5. Several early choices are heavier
than the current stage needs — the same shape as "we assumed Docker, but managed cloud
is simpler and free." These supersede the earlier text where they conflict. The
architecture (two planes, deterministic engine, signed receipts, shadow-first) is
unchanged and sound; these are **deferrals and managed-infra swaps**, not redesigns.

1. **Managed serverless stores instead of self-hosted PG/Redis — dev AND prod.**
   Use **Neon** (serverless Postgres) + **Upstash** (serverless Redis), free tier, zero
   ops, same `DATABASE_URL`/`REDIS_URL` the code already reads. Supersedes "run PG15 +
   Redis7 containers on Railway/Fly" in Task 6.1 and the local-Docker assumption.
   Docker stays only as (a) an optional local convenience and (b) the CI compose-smoke
   job. See `docs/running-locally.md`.

2. **Do NOT stand up a separate `policy-svc` (TypeScript/Node) yet.** A second
   runtime+deploy before a dashboard or TS-SDK exists is a premature boundary. For MVP,
   load policy as **JSON files / GitOps** (A#8) directly in `authorize-svc`, or add
   thin control-plane endpoints to the Go service. Introduce the separate TS policy-svc
   only when the dashboard lands (Phase 5). Affects Phase 2 sequencing.

3. **One SDK first, not two.** Build the SDK matching the first design partner's stack
   (Phase 4); generate the second from the same contract later.

4. **Dashboard: audit-viewer + "verify signature" slice first** (Task 5.1). A
   shadow-mode partner needs to read the audit and verify receipts, not a policy-
   authoring GUI (they author via JSON/GitOps). Defer the authoring UI and Clerk auth.

5. **Task 1.6: defer field-level encryption + per-tier retention.** Build the audit
   write as **append-only + tamper-evident hash chain + async (in-proc) write** with an
   in-memory store seam for hermetic CI tests. Field-level encryption of
   amount/target/counterparty and per-tier retention become a documented post-MVP TODO
   — they add real complexity to the *first* audit write without proving its value.

6. **Prod deploy (Task 6.1) simplifies accordingly:** app on a single host/platform
   (Railway/Fly/Render — one service), stores on Neon+Upstash, dashboard on Vercel when
   it exists. No self-managed stateful infra.

Unchanged and still required: Ed25519 decisions (A#1), authorize/capture (A#2),
determinism, the tamper-evident audit chain itself, shadow-first rollout.

---

## Phase map

| Phase | Goal | Exit criteria |
|---|---|---|
| **0 Foundations** | Repo, CI, local infra, **the schemas/algebra everything hangs on** | Contract frozen; truth-table tests exist (red) |
| **1 Decision plane** | Go `authorize-svc`: auth, engine, 6 local predicates, Ed25519 decisions, async audit | Real APPROVE/DENY from real policy; tamper test passes |
| **2 Policy + control plane** | Policy CRUD, versioning, bundle propagation, shadow mode | Publish a policy; nodes serve new version; shadow logs |
| **3 Stateful budgets** | Authorize/capture/void, atomic counters, no oversell | Concurrency test: N agents can't exceed a shared cap |
| **4 SDK + docs** | Python + TS SDK, generated docs, quickstart | 3-line integration works end-to-end |
| **5 Dashboard** | Policy authoring + audit viewer + decision verify UI | Non-engineer can author a policy + read the audit |
| **6 Design-partner deploy** | Deploy, observability, one partner in shadow | Partner runs real traffic in shadow for 2 weeks |

---

## Phase 0 — Foundations & Contracts

### Task 0.1 — Repo scaffold + local infra + CI
```
Repo: C:\Users\pokka\trust infra (Windows, PowerShell). This is the "AI Transaction Authorization
Infrastructure" company — deterministic policy-driven APPROVE/DENY/REVIEW middleware that sits
between AI agents and payment providers and NEVER moves money. Read PRD.md and TRD.md first; they
are canonical. Also read ROADMAP.md section A (critical fixes) — honor them.

TASK: Scaffold the monorepo. Layout:
  /services/authorize-svc   (Go, decision plane, hot path)
  /services/policy-svc      (Python or Node, control plane — pick and note why)
  /services/dashboard       (Next.js, later)
  /sdks/python  /sdks/ts
  /contracts                (OpenAPI + JSON Schemas + shared types — source of truth)
  /deploy                   (docker-compose for local Postgres 15 + Redis 7)
  /docs
Add: docker-compose bringing up Postgres 15 + Redis 7 one command; Go module for authorize-svc with
a /health endpoint returning 200 + build info; Makefile/taskfile with `up`, `test`, `run`; a CI
config (GitHub Actions) that builds + runs tests on push. Structured JSON logging from day one.

CONSTRAINTS: Go for authorize-svc (low-latency hot path — confirmed in TRD §4). No business logic
yet. Just the skeleton that builds, boots, connects to PG+Redis locally, and passes a health test.

ACCEPTANCE: `docker compose up` starts PG+Redis; `authorize-svc` boots, connects to both, /health
returns 200; CI is green; README documents how to run it.
```

### Task 0.2 — Freeze the contract (schemas)
```
Repo: C:\Users\pokka\trust infra. Read PRD.md, TRD.md, ROADMAP.md section A. Product = deterministic
AI transaction authorization middleware (Go), never moves money.

TASK: Define and FREEZE the core contract in /contracts as the single source of truth:
  1. AuthorizeRequest: agent_id, action, amount, currency, target{type,id}, jurisdiction,
     context(map), idempotency_key. Include the EXPLICIT evaluation inputs that make decisions
     deterministic and replayable: the orchestrator will inject `evaluated_at` (timestamp) and a
     `counter_snapshot` — document that predicates must never read wall-clock/network themselves
     (ROADMAP A#7).
  2. Decision (response + stored record): decision_id (ULID), verdict (APPROVE|DENY|REVIEW),
     policy_version_hash, explanation{summary, matched_rules[]{rule_id,type,result,detail,evidence}},
     obligations[], latency_ms, evaluated_at, signature (Ed25519 — ROADMAP A#1).
  3. Error: RFC 7807 shape.
Express as: OpenAPI 3.1 for the HTTP surface + JSON Schema for the objects + generated Go structs.
Version everything under /v1. Write the schemas so SDK types can be generated from them later.

CONSTRAINTS: This contract is what every other component depends on — make it complete and precise.
Decision signature is Ed25519 (asymmetric), NOT HMAC. Request auth signature (separate concern) is
HMAC — keep them clearly distinct in the schema/docs.

ACCEPTANCE: OpenAPI validates; Go structs generate and compile; a sample AuthorizeRequest and a
sample APPROVE + DENY Decision are checked into /contracts/examples and validate against the schema.
```

### Task 0.3 — Combination algebra + truth-table tests
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §5 (combination algebra) and §19 (testing). Product =
deterministic authorization engine.

TASK: Specify the verdict combination algebra as a pure, documented function and write it as
FAILING reference tests (TDD) in the authorize-svc Go module — the implementation comes in Phase 1.
Rules: any hard DENY ⇒ DENY; else any REVIEW ⇒ REVIEW; else all-satisfied ⇒ APPROVE; an enriched
predicate that could not complete is governed by its declared fail-mode (fail-closed default =
REVIEW or DENY, never a fabricated satisfy). Cover every combination as an explicit test case,
including the ComplianceAPI-style rows (sanctions BLOCK, spend EXCEEDED, jurisdiction BLOCKED,
REVIEW on a fuzzy match, upstream UNAVAILABLE → fail-closed). Target 100% branch coverage on this
function (non-negotiable per TRD §19).

ACCEPTANCE: A table-driven Go test file enumerating every verdict combination exists and currently
FAILS (no implementation yet). The intended behavior is unambiguous from the test names.
```

---

## Phase 1 — Decision Plane Core (Go)

### Task 1.1 — authorize-svc HTTP skeleton
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §1–3, §9. Building the decision plane (Go, hot path,
stateless). Contract is frozen in /contracts (Task 0.2).

TASK: Build the authorize-svc HTTP layer: `POST /v1/authorize` (returns a hardcoded APPROVE
conforming to the Decision schema for now), `GET /v1/health`, `GET /v1/decisions/{id}` (stub).
Wire config (env), graceful shutdown, structured request logging with a per-request id, and RFC 7807
error responses. No auth, no engine yet.

CONSTRAINTS: Stateless. Conform exactly to the frozen contract. Keep handlers thin — real logic goes
in an engine package next.

ACCEPTANCE: POST /v1/authorize returns a schema-valid APPROVE; errors are RFC 7807; integration test
hits the running service and validates the response against /contracts.
```

### Task 1.2 — Auth: API keys, HMAC request signing, replay protection
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §11 (security) and ROADMAP A#1 (HMAC is for REQUEST
auth only; decision signing is separate/Ed25519). Building authorize-svc auth.

TASK: Implement request authentication on /v1/authorize:
  - API keys: generate 256-bit keys (crypto-random), format azn_live_/azn_test_ prefix, store only
    sha256(key), constant-time compare (crypto/subtle). Redis cache of key→org (5-min TTL) with
    Postgres fallback.
  - HMAC request signing: client signs a canonical payload with the key secret; verify server-side
    constant-time; reject timestamp skew beyond N seconds (config).
  - Replay protection: per-key nonce cache in Redis (short TTL); reject reused nonces.
  - 401 missing/invalid key, 403 revoked, 429 later. RFC 7807 bodies.

CONSTRAINTS: Constant-time everywhere secrets are compared. Never log secrets or full keys. This is
security-critical code — write it carefully and normally (not terse).

ACCEPTANCE: Integration tests: valid signed request passes; wrong signature → 401; replayed nonce →
rejected; skewed timestamp → rejected; revoked key → 403. Seed a test key via a fixture.
```

### Task 1.3 — Rate limiting (3 layers)
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §11 rate limiting. authorize-svc.

TASK: Implement three-layer rate limiting: (1) per-key sliding window (Redis, atomic INCR+EXPIRE);
(2) per-key burst cap (≤10 req/sec via a 1-sec-TTL counter); (3) document the per-IP infra-level
throttle as a deploy concern (don't build it in-app). On limit: 429 + Retry-After. Limits come from
the key's tier.

ACCEPTANCE: Integration test drives a key past its per-minute and per-second limits and asserts 429 +
correct Retry-After; a key under the limit is unaffected. Concurrency-safe (no race under parallel
requests).
```

### Task 1.4 — Deterministic engine + 6 local predicates
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §5–6 and ROADMAP A#3 (aggregates are NOT in the local
engine), A#6 (no compiler), A#7 (time + counter are injected inputs). Task 0.3 truth-table tests
exist and are failing.

TASK: Implement the deterministic decision engine and 6 LOCAL predicate types (no external I/O, no
wall-clock inside predicates — `evaluated_at` and any needed state are passed in):
  per_transaction_limit, vendor_allowlist, vendor_blocklist, agent_permission (agent→allowed
  actions/targets), time_window (uses injected evaluated_at), jurisdiction_currency restriction.
Predicate interface: evaluate(ctx) -> {satisfied|denied|review, reason, evidence}. Engine resolves
applicable predicates from an in-memory policy object, evaluates local-first with short-circuit on
hard DENY, combines via the Phase-0 algebra, assembles the structured explanation. Budgets/sanctions
are OUT of this task (Phase 3 / enrichment).

CONSTRAINTS: Pure and deterministic — identical (request, policy, evaluated_at) ⇒ identical decision.
Make the Phase-0 truth-table tests pass.

ACCEPTANCE: Task 0.3 tests are green; each predicate has unit tests incl. deny/allow/review/evidence;
100% branch coverage on the combination function; explanation matches TRD §7 shape.
```

### Task 1.5 — Ed25519 decision signing + verifier
```
Repo: C:\Users\pokka\trust infra. Read ROADMAP A#1 and TRD.md §11 (as amended). CRITICAL: decision
signatures are ASYMMETRIC (Ed25519), not HMAC.

TASK: Sign every Decision with an Ed25519 private key (loaded from env/secret for MVP; KMS/HSM is a
Prod TODO — note it). Sign a canonical serialization of the decision fields (deterministic
canonicalization — define it). Publish the public key at a stable endpoint (e.g. GET /v1/keys/public
or a JWKS-style doc). Provide a standalone verify function + a CLI/test util that takes a Decision +
the public key and returns valid/invalid. Include `signature` in the response and stored record.

CONSTRAINTS: Canonicalization must be stable and documented (field order, number formatting) so
verification is reproducible by third parties. Rotating keys: support a key id in the signature so
old decisions verify against the right public key.

ACCEPTANCE: A produced Decision verifies with the published public key; mutating any signed field
fails verification; the verify util works independently of the signing service.
```

### Task 1.6 — Async audit write + tamper-evident record
> **AMENDED (A2#5):** for MVP, defer **field-level encryption** and **per-tier
> retention** — build append-only + hash-chain + async write first, with an in-memory
> store seam for hermetic CI tests (same pattern as auth/ratelimit). Encryption +
> retention are a documented post-MVP TODO.
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §12–13, §14 (async audit), ROADMAP A#10 (PII).
authorize-svc + Postgres.

TASK: Persist every decision to an append-only `decisions` table AFTER the response is returned
(async — do not add to response latency). Compute a record_hash chaining to the previous record for
the org (tamper-evidence). Store policy_version_hash, matched_rules, explanation (JSONB), signature.
Field-level encryption on sensitive fields (amount/target/counterparty) with configurable retention
per tier. Implement GET /v1/decisions/{id} (returns record + signature_verified computed at read)
and GET /v1/decisions (paginated, filter by agent/verdict/date).

CONSTRAINTS: Append-only (no UPDATE/DELETE on decisions). Async write must not block or drop on
response — use a durable-enough in-proc queue for MVP, note the upgrade to a real queue.

ACCEPTANCE: A decision is retrievable with signature_verified:true; mutating a stored row breaks the
hash chain and signature_verified:false; audit write does not appear in the request's latency_ms;
pagination + filters work.
```

### Task 1.7 — End-to-end wiring + integration + tamper test
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §19. Wire Tasks 1.1–1.6 together.

TASK: Full path: signed request → auth → rate limit → engine (loads a policy fixture) → real
APPROVE/DENY → Ed25519-signed decision → async audit. Replace the hardcoded APPROVE. Add integration
tests against real test PG+Redis (docker): valid APPROVE, a DENY per predicate, 401/403/429 paths,
the tamper test, and an idempotency-key test (same key ⇒ same decision, no duplicate side effects —
note budgets aren't wired yet so this is currently side-effect-free).

ACCEPTANCE: End-to-end integration suite green in CI; p99 local-decision latency measured and
reported (target <50ms MVP); no secret leakage in logs/errors.
```

---

## Phase 2 — Policy & Control Plane

### Task 2.1 — Policy schema + validation + versioning + signing
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §6 and ROADMAP A#4, A#6. Building the control plane
(policy-svc). NO compiler — validate + version + hash + sign declarative JSON.

TASK: Define the JSON policy schema covering the 6 local predicate types (Task 1.4) plus placeholders
for budget + enrichment predicates (Phase 3/enrichment). A policy belongs to an org, targets one or
more agents, and lists typed rules. On publish: validate against schema → assign an immutable
content-hash version → Ed25519-sign the version → store in policy_versions. Support draft vs
published, list versions, and rollback (republish a prior hash).

ACCEPTANCE: Author a policy, publish it, get a version hash; edit + republish creates a new immutable
version; invalid policy is rejected with a clear error; rollback restores a prior version.
```

### Task 2.2 — policy-svc API + bundle propagation to decision nodes
```
Repo: C:\Users\pokka\trust infra. Read ROADMAP A#4 (stale policy = wrong decision). policy-svc +
authorize-svc.

TASK: Expose policy CRUD + publish over /v1/policies. Implement bundle propagation: when a version is
published, decision nodes must converge to it. MVP mechanism: decision nodes cache the active bundle
per org and refresh via short-TTL pull (or subscribe) ; each decision records the exact
policy_version_hash used; add GET /v1/policies/active so a customer sees which version is serving.
The decision plane must NEVER make a synchronous call to policy-svc on the hot path — it reads its
local cached bundle (TRD §3 boundary rule).

ACCEPTANCE: Publish a new version → within the convergence window, authorize decisions cite the new
hash; killing policy-svc does NOT stop the decision plane serving the last-known-good bundle;
GET /v1/policies/active reflects reality.
```

### Task 2.3 — Shadow mode + simulate
```
Repo: C:\Users\pokka\trust infra. Read PRD.md §6, §9 (shadow mode is the adoption wedge) and
ROADMAP A#5 (advisory-first) and A#9. authorize-svc + policy-svc.

TASK: Shadow mode: a policy/key can run in log-only mode — the engine evaluates and records the
decision but the response signals "shadow" so the caller does NOT enforce. Add
POST /v1/policies/{id}/simulate to dry-run a policy version against a supplied set of historical
requests and return what it WOULD have decided (for the "what would this policy have done last week"
demo).

ACCEPTANCE: A shadow-mode key gets evaluated decisions in the audit log marked shadow; simulate
returns per-request would-be verdicts for a batch; no shadow decision is presented as enforceable.
```

---

## Phase 3 — Stateful Budgets (the hard part)

### Task 3.1 — Authorize / capture / void (two-phase)
```
Repo: C:\Users\pokka\trust infra. Read ROADMAP A#2 (auth vs capture) CAREFULLY — this is the design
that keeps budgets correct. authorize-svc.

TASK: Make budget-affecting authorizations two-phase:
  - POST /v1/authorize evaluates AND, if it would consume budget, places a HOLD (reservation) with a
    TTL; returns APPROVE + a hold reference on the decision.
  - POST /v1/authorize/{id}/capture commits the held amount (call after the downstream payment
    succeeds). Idempotent.
  - POST /v1/authorize/{id}/void releases the hold (call if the payment fails/aborts). Idempotent.
  - Holds auto-expire on TTL (released back to budget) so a crashed caller can't leak budget.
Idempotency keys ensure a retried authorize returns the same decision + same hold (no double hold).

CONSTRAINTS: Non-budget authorizations skip holds (pure evaluation). Capture/void must be idempotent
and safe under retries. Document the state machine (evaluated→held→captured|voided|expired).

ACCEPTANCE: Tests: authorize→capture commits budget; authorize→void releases; authorize→(no action)→
TTL expiry releases; retried authorize with same idempotency key does not double-hold; capture after
void is rejected.
```

### Task 3.2 — Atomic budget counters + reconciliation + no-oversell
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §17 (budget is THE bottleneck; hard caps need a central
atomic op). Building the accumulator predicate (ROADMAP A#3 — this lives OUTSIDE the local engine and
injects a boolean into the decision context).

TASK: Implement rolling/monthly/daily budget predicates backed by atomic Redis counters
(reservations from Task 3.1 count against them), with Postgres as source of truth and async
reconciliation. The predicate computes spend_to_date + amount vs limit and returns
WITHIN_LIMIT/EXCEEDED with evidence. Windows: month (32-day TTL), day, rolling. Concurrency: N
parallel authorizations against one shared cap must NEVER oversell.

CONSTRAINTS: Hard caps require the central atomic op (document the latency cost per TRD §17). If Redis
is unavailable, budget predicates FAIL-CLOSED (REVIEW/DENY), never silently satisfy.

ACCEPTANCE: A concurrency test fires many simultaneous authorizations at a cap and asserts total
approved+held ≤ limit (no oversell); window rollover resets correctly; Redis-down → budget predicate
fails closed; reconciliation keeps PG and Redis consistent.
```

---

## Phase 4 — SDK & Developer Experience

### Task 4.1 — Python SDK
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §10 and PRD.md §9. Types generate from /contracts.

TASK: Build the Python SDK: authorize(txn), shadow(txn), capture(id), void(id), verify_decision(dec)
using the published Ed25519 public key. It canonicalizes + HMAC-signs requests, handles nonces +
timestamps, and exposes on_unavailable = FAIL_CLOSED (default) | FAIL_OPEN | LOCAL_CACHE. Typed
models generated from the OpenAPI/JSON Schema. Typed exceptions mirroring RFC 7807. NEVER swallow an
upstream failure into a silent APPROVE.

ACCEPTANCE: A 3-line example integrates authorize before a mock payment call and enforces the verdict;
verify_decision validates a real signed decision; fail-mode behavior is unit-tested; publishable
package metadata present.
```

### Task 4.2 — TypeScript SDK
```
Repo: C:\Users\pokka\trust infra. Mirror Task 4.1 for TypeScript/Node. Same surface, same fail-mode
config, types generated from /contracts, decision signature verification included.

ACCEPTANCE: 3-line TS integration works end-to-end against the running service; sig verification and
fail-modes unit-tested; package builds.
```

### Task 4.3 — Docs + quickstart from OpenAPI
```
Repo: C:\Users\pokka\trust infra. Read TRD.md (DX) + the README plan. Generate, don't handwrite.

TASK: Auto-generate API reference from the OpenAPI spec (Scalar or Redocly). Write a <10-step
quickstart: get key → install SDK → authorize before your payment → read the audit → verify a
decision. One landing/docs page. Include verdict definitions and fail-mode guidance.

ACCEPTANCE: Docs build from the spec and stay in sync; a new engineer can go key→first authorize in
<15 min following only the quickstart.
```

---

## Phase 5 — Dashboard (Control Plane UI)

### Task 5.1 — Next.js dashboard
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §1 (control plane), PRD.md personas. Next.js +
TypeScript + Tailwind + shadcn/ui, auth via Clerk. Talks to policy-svc + audit read APIs.

TASK: Four areas: (1) Overview — decision volume, verdict mix, p50/p95 latency, active policy
version. (2) Policy authoring — create/edit/publish policies for the 6 predicate types + budgets,
show version history + rollback; ALSO document a policy-as-files/GitOps import path (ROADMAP A#8) as
a stretch. (3) Audit log — filterable table (agent/verdict/date), row → decision receipt. (4)
Decision receipt — printable, shows inputs, matched rules, policy version hash, and an in-browser
"Verify signature" button using the published Ed25519 public key. API keys: create-once modal +
revoke.

ACCEPTANCE: A non-engineer can author + publish a policy and read the audit; the receipt's Verify
button confirms a real signature client-side; keys can be created (shown once) and revoked.
```

---

## Phase 6 — Design-Partner Deploy & Observability

### Task 6.1 — Deploy + observability + partner onboarding
```
Repo: C:\Users\pokka\trust infra. Read TRD.md §16–18. Ship it.

TASK: Deploy authorize-svc + policy-svc + PG + Redis (Railway/Fly), dashboard on Vercel, HTTPS,
security headers, Sentry, a status page polling /v1/health. Wire OpenTelemetry tracing across
authorize→predicates; metrics for latency histograms, verdict distribution, enrichment
timeout/error rate, rate-limit hits, active bundle version; alerts on latency SLO burn and enrichment
degraded (5 consecutive fails). Onboard ONE design partner in SHADOW mode (ROADMAP A#5 advisory-
first): give them a key + SDK, they run real agent traffic log-only for 2 weeks, review the audit
together, then flip ONE agent to enforce.

ACCEPTANCE: Live URLs; dashboards show real decision metrics; a design partner is making real shadow
authorizations; the shadow→enforce flip on one agent is the go/no-go signal for the whole MVP.
```

---

## Cross-cutting (fold into the phases, don't skip)

- **Threat-model tests** (TRD §20): signature forgery, replay, injection, oversized payload, authz-bypass — add to each relevant phase's suite.
- **Load + chaos** (TRD §19): p99 under target RPS; kill Redis / kill policy-svc / kill enrichment → assert declared degradation, never a silent wrong APPROVE.
- **Contract tests**: SDKs vs OpenAPI so schema drift breaks CI.
- **Legal**: get a lawyer's read on inline advisory→enforcing liability BEFORE any production enforce-mode (ROADMAP A#5).

---

## Order of operations (the short version)

Freeze the **schema + algebra + Ed25519 signing** first — those are the non-negotiable spine. Then the Go decision plane on local predicates. Then policy + shadow mode → put it in a design partner's hands in shadow ASAP (before budgets, before dashboard). Budgets (two-phase) and the dashboard come after you have a human running real traffic. Determinism, signing, and audit must be provably right before you add breadth.

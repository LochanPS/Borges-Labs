# Technical Requirements & Architecture Blueprint — AI Transaction Authorization Infrastructure

*Companion to [PRD.md](PRD.md). Canonical identity: authorization middleware returning deterministic APPROVE/DENY/REVIEW before a payment reaches the provider. Never moves money. Written to support a venture-scale infra company while defining an achievable MVP. Decisions are labeled **[MVP] / [Prod] / [5yr]**.*

---

## 1. Architecture Overview — Two Planes

The single most important structural decision: split the system into a **decision plane** (hot, stateless, latency-critical) and a **control plane** (warm, stateful, not in the payment path). They fail independently. The payment path never depends on the control plane being up.

```
                         CONTROL PLANE  (not in payment path)
   policy owner ──▶ Policy API ──▶ Policy Store (Postgres) ──▶ Policy Compiler
                        │                                          │
                        │                              compiled, versioned, signed
                        │                                    policy bundle
                        ▼                                          │
                    Audit Store  ◀── async decision log ───────────┼───────┐
                    (append-only)                                   ▼       │
   ────────────────────────────────────────────────────────────────────── │ ──
                          DECISION PLANE  (in payment path)                 │
                                                                            │
   AI agent ──▶ SDK ──▶ Authorize API ──▶ Decision Engine ──▶ Policy Eval  │
      │                    (Go)              (Go, stateless)   (bundle)     │
      │                       │                    │                        │
      │                       │            (enriched predicates)            │
      │                       │            ┌───────┴────────┐               │
      │                       │       Budget counters   Sanctions/          │
      │                       │       (Redis, atomic)   vendor risk (ext)   │
      │                       ▼                                             │
      │◀──── signed decision (APPROVE/DENY/REVIEW + explanation) ───────────┘
      ▼
   existing Payment Provider ──▶ Bank
```

**Why each piece exists**
- **SDK** — thin wrapper: signs the request, calls the API, verifies the signed decision, applies fallback if unreachable. [MVP]
- **Authorize API (Go)** — auth, validation, rate limit, hand to engine. Stateless. [MVP]
- **Decision Engine (Go)** — orchestrates predicate evaluation against the active policy bundle; assembles verdict + explanation; signs it. Pure function of (request, bundle, counters). [MVP]
- **Policy Store + Compiler** — authored policy → validated → compiled to an immutable, versioned, hash-identified bundle. Decisions cite the bundle hash. [MVP]
- **Budget counters (Redis)** — atomic spend-to-date accumulators. The one piece of shared mutable state in the hot path. [P1]
- **Enrichment (external)** — sanctions/vendor risk. Best-effort, timeout-bounded, fail-policy-governed. [P1]
- **Audit Store** — append-only decision log written asynchronously. Never blocks the response. [MVP]

---

## 2. Request Flow (sequence)

```
Agent → SDK: authorize(txn)
SDK → SDK: canonicalize + HMAC-sign + nonce
SDK → Authorize API: POST /v1/authorize  (X-Api-Key, X-Signature, X-Nonce, X-Timestamp)
Authorize API: verify key (Redis→PG) → verify signature (constant-time) → check nonce (replay) → rate limit
Authorize API → Engine: evaluate(request, active_bundle)
Engine: run LOCAL predicates (µs) → short-circuit on first hard DENY
Engine: if bundle needs them, run ENRICHED predicates concurrently (bounded timeout)
Engine: assemble verdict + explanation → sign decision
Authorize API → SDK: 200 { verdict, decision_id, explanation, policy_version, signature }
Authorize API → Audit (async BackgroundTask/queue): append decision record + record_hash
SDK → SDK: verify decision signature
SDK → Agent: APPROVE → proceed to payment provider | DENY → abort
```

---

## 3. Services & Boundaries [MVP→Prod]

- **`authorize-svc` (Go)** — decision plane. Stateless. Scale horizontally behind an LB.
- **`policy-svc` (Python/Node ok)** — control plane. Policy CRUD, compilation, versioning, bundle publication.
- **`audit-svc`** — write path async, read path for dashboard/API. Append-only.
- **`admin/dashboard`** — Next.js UI over control-plane APIs.

Boundary rule: the decision plane may **read** a cached policy bundle and **write** async audit events; it must never make a *synchronous* call to the control plane. That's what keeps availability independent.

---

## 4. Language / Runtime — Decision Matrix

| Option | Latency/concurrency | Ecosystem | DX/velocity | Verdict |
|---|---|---|---|---|
| **Go** | Excellent; GC low-pause; great concurrency | Strong for infra/services | High | **Decision plane [MVP]** |
| **Rust** | Best; no GC; ideal for a policy VM | Steeper; slower iteration | Lower early | **Reserve for the policy evaluator core [Prod]** (or adopt Cedar, which is Rust) |
| **Python/FastAPI** | Weakest under concurrent inline load | Richest | Highest | **Control plane + dashboard + SDK reference only** |

**Recommendation:** Go for `authorize-svc` (confirms the earlier decided stack). Python is fine for control plane and the ComplianceAPI demo, **not** for the hot path. If the policy evaluator becomes a bottleneck or you adopt Cedar, that core is Rust.

---

## 5. Authorization Engine

- **Inputs:** `{agent_id, principal/owner, action, target (account/vendor), amount, currency, jurisdiction, timestamp, arbitrary context map}` + the active compiled policy bundle + (for stateful predicates) counter reads.
- **Output:** `{verdict: APPROVE|DENY|REVIEW, decision_id (ULID), matched_rules[], explanation, policy_version, obligations[], signature}`.
- **Pipeline:** normalize → resolve applicable policy set for (agent, org) → evaluate predicates (local first, short-circuit on hard DENY) → combine per **combination algebra** → assemble explanation → sign.
- **Combination algebra (deterministic, documented):** any hard DENY ⇒ DENY. Else any REVIEW flag ⇒ REVIEW. Else all-satisfied ⇒ APPROVE. Enriched-predicate failure ⇒ governed by the predicate's declared fail-mode (see §21). *This is the same shape as the ComplianceAPI verdict table — that table is a subset.*
- **Extensibility:** predicates are typed, versioned plugins with a fixed interface `evaluate(ctx) → {satisfied|denied|review, reason, evidence}`. New rule types add a predicate; no engine redesign. Determinism is enforced by forbidding wall-clock/random/network inside *local* predicates (network only via declared enrichment predicates).

---

## 6. Policy Engine — The Central Decision Matrix

| Approach | Expressiveness | Determinism/analyzability | Safety (customer-authored) | Ops complexity | Verdict |
|---|---|---|---|---|---|
| **Hand-rolled JSON rules + custom evaluator** | Low–medium | High (you control it) | High (constrained schema) | Low | **[MVP]** — ship this |
| **Custom DSL** | High | You must guarantee it | Medium | High (you own a language) | Avoid — don't invent a language early |
| **OPA / Rego** | Very high | Good; general-purpose | Medium (Rego is powerful, footguns) | Medium (sidecar model mature) | Strong **[Prod]** candidate |
| **AWS Cedar** | High, purpose-built for *authorization* | Excellent — designed to be analyzable/provable; Rust-fast | High (least-privilege by design) | Medium | **Recommended [Prod]** |

**Recommendation:**
- **[MVP]** a constrained, declarative **JSON policy schema** (limit, budget, allowlist, blocklist, agent-permission, time, jurisdiction, currency) evaluated by your deterministic Go engine. Small surface, safe, fast, easy to explain.
- **[Prod]** migrate the policy language to **Cedar** (purpose-built for authorization, formally analyzable — you can *prove* "no policy can approve > $X", a killer enterprise feature) or OPA/Rego if Cedar's model proves too rigid for financial predicates. Keep the JSON schema as sugar that compiles down.

Why not Rego at MVP: it's a general policy engine, powerful but easy to write non-obvious rules in; Cedar's authorization-specific, analyzable model fits "least privilege for agents" better and supports the moat feature (provable bounds). But adopting either at MVP adds a runtime dependency before you've validated demand — hence JSON-first.

**Policy compilation & versioning:** authored policy → validated → compiled bundle → content-hash → signed → published. Every decision cites the bundle hash. Rollback = republish a prior hash. This gives reproducible decisions and defensible audits.

---

## 7. Explainability Model

Every decision carries a structured, machine- and human-readable explanation.

```json
{
  "decision_id": "dec_01HXYZ...",
  "verdict": "DENY",
  "policy_version": "pol_v3_9f2a1c...",
  "summary": "Transaction exceeds the monthly budget for procurement-agent.",
  "matched_rules": [
    {
      "rule_id": "monthly_budget",
      "type": "rolling_budget",
      "result": "DENIED",
      "detail": "spend_to_date=48200.00 + amount=5000.00 = 53200.00 > limit=50000.00 USD (window=2026-08)",
      "evidence": {"window":"2026-08","spend_to_date":48200.00,"limit":50000.00}
    }
  ],
  "obligations": [],
  "evaluated_at": "2026-08-27T10:32:11Z"
}
```

Rules of the format: name the exact rule, the numbers that drove it, the policy version, and a plain-English summary. An APPROVE lists satisfied rules the same way. This is what a policy owner hands an auditor.

---

## 8. Decision Tokens & Availability Decoupling [Prod] — challenge to the "pure inline" model

Pure synchronous inline authorization means *your* outage = *customer's* payments stop. Unsellable at 99.99% unless you engineer around it. Three mitigations, layered:

| Mechanism | What it buys | Cost |
|---|---|---|
| **Signed decision token** | Agent requests authorization slightly ahead of execution, receives a short-TTL signed token, presents it at payment time. Decouples decision from the exact execution instant. | Small protocol complexity |
| **SDK local-cache fallback** | On unreachable API, SDK evaluates a *cached local bundle* for local predicates (no budget/enrichment) per the configured fail-mode. | Bundle distribution to SDK |
| **Sidecar/edge evaluation** | Bundle runs in a sidecar at the customer's edge; decisions are local (sub-ms), central plane only publishes bundles + ingests audit async. OPA/Cloudflare model. | Deploy/operate sidecar |

**Recommendation:** [MVP] hosted API + SDK fail-mode config (fail-closed default). [Prod] add signed tokens, then sidecar for latency-and-availability-sensitive customers. Signed decisions (already a decided item) are the foundation for all three.

---

## 9. API Design [MVP]

Versioned `/v1/`. Breaking changes → `/v2/`, `/v1/` maintained. RFC 7807 errors. Every request: `X-Api-Key`, `X-Signature` (HMAC), `X-Nonce`, `X-Timestamp`.

**`POST /v1/authorize`**
```json
// request
{ "agent_id":"procurement-agent-v2", "action":"payment.create",
  "amount":5000.00, "currency":"USD", "target":{"type":"vendor","id":"acme-supplies"},
  "jurisdiction":"US", "context":{"invoice_id":"inv_88"}, "idempotency_key":"..." }
// response
{ "verdict":"APPROVE", "decision_id":"dec_01HXYZ", "policy_version":"pol_v3_9f2a1c",
  "explanation":{...}, "obligations":[], "latency_ms":7, "signature":"..." }
```
- **`POST /v1/authorize/{id}/capture`** / **`POST /v1/authorize/{id}/void`** — two-phase budget: `authorize` evaluates + places a TTL hold on budget; `capture` commits it after the payment succeeds; `void` releases it on failure. Both idempotent; holds auto-expire. *Without this, an APPROVE followed by a failed payment leaks budget — see ROADMAP §A#2.*
- **`GET /v1/decisions/{id}`** — full record + `signature_verified`.
- **`GET /v1/decisions`** — paginated, filter by agent/verdict/date.
- **`GET /v1/health`** — decision-plane liveness + enrichment upstream status.
- **Control plane:** `POST/GET/PUT /v1/policies`, `POST /v1/policies/{id}/publish`, `GET /v1/policies/{id}/versions`, `POST /v1/policies/{id}/simulate` (shadow/dry-run), `POST /v1/keys`, `DELETE /v1/keys/{id}`.

Idempotency keys on `authorize` so a retried request returns the same decision (determinism + safety).

---

## 10. SDK Strategy

- **Languages:** Python + TypeScript [MVP]; Go, Java [Prod].
- **Structure:** thin. Responsibilities = canonicalize request, sign (HMAC), call API, verify decision signature, apply fallback per config, expose `authorize()` + `shadow()`.
- **DX:** one-call integration; typed models generated from the OpenAPI spec; explicit `on_unavailable = FAIL_CLOSED | FAIL_OPEN | LOCAL_CACHE`.
- **Errors:** typed exceptions mirroring RFC 7807; never swallow an upstream failure into a silent APPROVE.

---

## 11. Authentication & Security [MVP]

- **API auth:** per-key. Store only `sha256(key)`; generate with `secrets.token_urlsafe(32)` equivalent (256-bit). Compare constant-time (`hmac.compare_digest`). Prefixes `azn_live_` / `azn_test_`.
- **Request signing (customer→us):** HMAC over a canonical payload + timestamp; reject skew > N seconds. Symmetric is fine here — the caller holds the key.
- **Decision signing (us→everyone) — ASYMMETRIC, not HMAC:** sign each Decision with an **Ed25519** private key (KMS/HSM at Prod). Publish the public key (JWKS-style). Customers *and third parties* (auditors, regulators) verify without any secret. HMAC would let a key-holder forge our decisions — unacceptable for an audit artifact. Canonicalization of signed fields must be stable + documented; include a key id for rotation. *(Corrects the earlier conflation — see ROADMAP §A#1.)*
- **Replay protection:** per-key nonce cache (Redis, short TTL); reject seen nonces.
- **Key rotation:** overlapping active keys; rotate without downtime; revoke = immediate.
- **Secrets:** platform secret manager (Railway/Vault); never in git. Decision-signing private key in a KMS/HSM [Prod].
- **Encryption:** TLS in transit; encrypt policy configs at rest; minimize retained sensitive data (store references, not raw account numbers where possible).
- **Rate limiting:** 3 layers — per-key sliding window, per-IP infra throttle, per-key burst cap.
- **Input validation:** strict schemas; reject oversized bodies; ORM-only parameterized queries.

---

## 12. Data Model [MVP]

```
organizations   id · name · created_at
principals       id · org_id · type(human|service) · name        -- owners of agents
agents           id · org_id · principal_id · name · status · created_at
api_keys         id · org_id · key_hash(unique) · prefix · scopes · is_active · rate_limit_rpm · created_at · last_used_at
policies         id · org_id · name · status(draft|published) · created_at
policy_versions  id · policy_id · version_hash(unique) · compiled_bundle(JSONB) · signature · published_at · author
budgets          id · org_id · agent_id · window(month|day|rolling) · limit · currency        -- source of truth
                 (fast counters live in Redis: budget:{agent}:{window} atomic; reconciled to PG)
decisions        id(ULID) · org_id · api_key_id · agent_id · action · amount · currency · target
                 · jurisdiction · verdict · matched_rules(JSONB) · explanation(JSONB)
                 · policy_version_hash · latency_ms · record_hash · signature · created_at
nonces           key_id · nonce · expires_at         -- replay (Redis, TTL)
```
Indexes: `decisions(org_id, created_at)`, `decisions(agent_id, created_at)`, `api_keys(key_hash)`, `policy_versions(version_hash)`. `record_hash` chains for tamper-evidence.

---

## 13. Storage Strategy — Matrix

| Store | Role | Verdict |
|---|---|---|
| **PostgreSQL** | Source of truth: orgs, agents, keys, policies/versions, decisions, budgets | **Primary [MVP]** |
| **Redis** | Hot path: key-lookup cache, rate-limit + nonce, **atomic budget counters** | **[MVP]** |
| **Append-only event log** (Postgres partitioned table → Kafka/object store later) | Immutable audit stream | Postgres table [MVP] → stream [Prod] |
| Document DB | Not needed; JSONB in PG covers flexible fields | Reject |

Rationale: one relational source of truth keeps determinism and audit integrity simple; Redis serves only the microsecond-sensitive shared state. Don't add a document DB for flexibility JSONB already gives you.

---

## 14. Event Architecture — Matrix

| Option | Fit for us | Verdict |
|---|---|---|
| **Synchronous only** | The *decision* must be sync (it's inline). | **Decision = sync [MVP]** |
| **Async audit writes** (in-proc queue / BackgroundTasks) | Decouple audit persistence from response latency | **[MVP]** |
| **NATS** | Lightweight, fast, simple ops; good for internal fan-out | **[Prod] internal bus** |
| **Kafka** | Durable, replayable audit stream; heavy ops | **[Prod/5yr] audit backbone** when volume justifies |
| **RabbitMQ** | Task queues; more than we need | Reject for MVP |

**Recommendation:** the decision path is synchronous by nature. Everything *after* the decision (audit, metrics, budget reconciliation, webhooks) is async. [MVP] in-process background writes → durable queue. [Prod] NATS internally, Kafka as the audit/event backbone once decision volume is high.

---

## 15. Deployment Models

- **[MVP] Cloud SaaS** — hosted multi-tenant. Railway/Fly/managed. Fastest adoption.
- **[Prod] Self-host + private cloud** — Docker/Helm; control plane + decision plane deployable in customer VPC (regulated buyers demand it).
- **[Prod] Sidecar/gateway** — decision plane as a sidecar next to the agent for local eval (see §8).
- **[5yr] Region-specific** deployments for data-residency.

The engine must stay deployment-agnostic — same bundle format, same evaluator, whether hosted, sidecar, or self-host.

---

## 16. High Availability & DR

- Stateless decision nodes ≥ 2 AZs behind an LB; scale out, no sticky state.
- Postgres primary + sync replica; automated failover. Redis with replica/Sentinel.
- Policy bundles cached in each decision node (and later sidecar) so a control-plane or DB blip doesn't stop decisions on local predicates.
- Health checks per node + per enrichment upstream (drives §21).
- DR: point-in-time PG backups; audit log is append-only and replicable; documented RPO/RTO. Signing keys backed in KMS with rotation.

---

## 17. Scalability & Bottlenecks

- Horizontal scale of stateless `authorize-svc` = linear for local predicates.
- **The bottleneck is the stateful budget counter** — concurrent agents decrementing a shared limit require atomic ops and can't be purely edge-local without a consistency compromise. Options: Redis atomic INCR (strong, central) vs. sharded/approximate local budgets with async reconciliation (fast, eventually-consistent — acceptable for soft limits, not for hard regulatory caps). **Call this out to customers: hard budget caps cost a central round trip; soft budgets can be edge-local.**
- Cache policy bundles; cache key lookups; keep enrichment behind bounded timeouts + circuit breakers so a slow upstream can't exhaust workers.

---

## 18. Observability

- **Logging:** structured JSON per decision (id, verdict, policy hash, latency, timeouts) to stdout → aggregator.
- **Tracing:** OpenTelemetry spans across authorize → predicates → enrichment; every decision traceable.
- **Metrics:** decision latency histogram (p50/p95/p99), verdict distribution, enrichment timeout/error rate, rate-limit hits, bundle version in use.
- **Dashboards + alerting:** latency SLO burn, enrichment upstream degraded (5 consecutive fails → alert), error budget, per-tenant volume near limits.

---

## 19. Testing Strategy

- **Unit:** combination algebra (100% branch — every verdict combination), each predicate, hash/signature, constant-time compare, validation. Deterministic and fast.
- **Integration:** full authorize flow against real test PG/Redis; every endpoint + status code; replay rejection; rate-limit; shadow mode; tamper test (mutated decision fails `signature_verified`/`record_hash`).
- **Contract tests:** SDKs against the OpenAPI spec so schema drift breaks CI.
- **Performance:** load test p99 under target RPS; verify budget-counter correctness under concurrency (no oversell).
- **Chaos:** kill enrichment upstream, kill Redis, kill a decision node → assert declared degradation (§21), never a silent wrong APPROVE.
- **Security:** authz bypass attempts, signature forgery, injection, oversized payloads.

---

## 20. Threat Model (STRIDE-oriented)

| Threat | Vector | Mitigation |
|---|---|---|
| Spoofing | Forged authorize request | Per-key HMAC signing + constant-time verify |
| Tampering | Altered decision in transit / altered audit record | Signed decisions; hash-chained append-only audit |
| Repudiation | "We never got that decision" | Signed, logged decision with policy hash + idempotency key |
| Info disclosure | Leaking policy/PII | Minimize retained data; encrypt at rest; response-model enforcement; no stack traces |
| DoS | Flood the inline API | 3-layer rate limiting; infra ingress limits; circuit breakers |
| Elevation | Agent gets authority it shouldn't | Least-privilege policies; deny-by-default; Cedar analyzability [Prod] |
| Replay | Resend a valid APPROVE | Nonce cache + timestamp skew rejection + short-TTL decisions |
| Supply chain | Compromised enrichment vendor returns bad data | Treat enrichment as untrusted best-effort; fail-mode governs; never let it silently flip DENY→APPROVE |

---

## 21. Failure Modes & Graceful Degradation

**Governing principle: fail predictably, and never emit a silent wrong APPROVE.**

| Component fails | Behavior |
|---|---|
| **Enrichment upstream** (sanctions/vendor risk) | Bounded timeout + one retry → mark predicate `UNAVAILABLE`. Per-predicate declared fail-mode: **fail-closed** (verdict = REVIEW/DENY with reason) is the safe default for regulated predicates. Never fabricate CLEAR. |
| **Policy engine / bundle load** | Serve last-known-good cached bundle (immutable, hash-checked). If none, return a controlled 503, not a guess. |
| **Postgres (control plane)** | Decision plane keeps deciding on local predicates from cached bundle + Redis counters. Policy edits pause; decisions continue. |
| **Redis** | Budget/rate/nonce degraded. Hard budgets can't be enforced → those predicates fail-closed (REVIEW/DENY). Local non-stateful predicates still evaluate. |
| **Latency spike** | Circuit breakers shed enrichment; return local-only decision with an obligation noting enrichment was skipped (if customer allows), else REVIEW. |
| **Whole service unreachable** | SDK applies configured `on_unavailable`: fail-closed (default), fail-open (customer opt-in, logged), or local-cache eval. |

The customer *chooses and sees* the fail-mode. That transparency is the product's integrity.

---

## 22. Moat Analysis

| Candidate moat | Strength | Note |
|---|---|---|
| **Latency + availability engineering** (sidecar/edge, tokens) | Medium-High | Hard to replicate well; directly felt |
| **Policy engine analyzability** (provable bounds via Cedar) | High | "Prove no policy can approve > $X" is a unique enterprise sell |
| **Audit/trust record** | Medium | Switching cost once it's the system of record for decisions |
| **Integrations breadth** (payment providers, agent frameworks) | Medium | Table stakes over time |
| **Trust network / data effects** | High [5yr] | Cross-customer agent/vendor reputation — compounding, defensible |
| **Developer experience** | Medium | Wins early adoption, not durable alone |

Strongest durable moats: **provable-policy analyzability** (near-term differentiator) → **trust-network data effects** (long-term). Latency/DX win the first customers; they don't keep them alone.

---

## 23. Technical Debt Forecast (acceptable MVP shortcuts → evolution)

| MVP shortcut | Why ok now | Must evolve to |
|---|---|---|
| JSON policy schema, no formal language | Small safe surface, ship fast | Cedar/OPA compiled from the schema [Prod] |
| Hosted-only, synchronous | Fastest adoption | Signed tokens → sidecar/edge [Prod] |
| Async audit via in-proc background | Fine at low volume | Durable queue → Kafka backbone [Prod] |
| Budgets in Redis, reconciled to PG | Works at low concurrency | Sharded/consistent accumulator design [Prod] |
| Manual billing from audit counts | Validate demand first | Metered billing after 5 paying customers |
| No REVIEW workflow | Approve/Deny validates core | Approval queue [P1] |

---

## 24. Five-Year Technical Roadmap

- **Year 1 — Prove the primitive.** Hosted authorize API, JSON policy, signed decisions, audit, shadow mode, Python/TS SDKs, first design partners flip to enforce. Sanctions pack as optional beachhead.
- **Year 2 — Harden + decouple.** Cedar policy language + analyzer, stateful budgets, REVIEW/approval workflows, decision tokens, self-host, SOC 2. NATS internal bus.
- **Year 3 — Edge + scale.** Sidecar/edge evaluation, Kafka audit backbone, multi-region/data-residency, Go/Java SDKs, deep payment-provider + agent-framework integrations.
- **Year 4 — Network.** Cross-customer trust/reputation signals, policy-pack marketplace, governance analytics.
- **Year 5 — Platform.** The authorization layer becomes the trust substrate other services build on; ecosystem + partner deployments.

Each step strengthens the authorization mission; none turns us into a PSP, bank, fraud tool, or governance suite.

---

## 25. Competitive Landscape & Differentiation

| Category | Examples | They answer | We answer |
|---|---|---|---|
| Payment infra | Stripe, Adyen | Can this payment be processed? | Should this agent make it? |
| Identity/authz (human) | Auth0, Okta | Who is the user? | Is this *agent action* authorized? |
| Policy engines | OPA, Cedar | General resource authorization | Financial-transaction authorization, inline, explainable, with audit |
| Fraud | Sift, Sardine | Is this probably fraud? (ML score) | Is this *permitted*? (deterministic policy) |
| Agent identity | "KnowYourAgent"-type | Do I trust this agent at receipt (merchant)? | May this agent execute, at initiation (operator)? |

**Differentiation:** we're the *deterministic, explainable authorization decision for agent-initiated payments, inline before execution, vendor- and framework-neutral, with a defensible audit trail.* Not a score, not identity, not settlement — the missing "should this happen" layer.

---

## 26. Immediate Next Steps (build order)

1. Lock the request/decision schema + combination algebra (the contract everything hangs on).
2. `authorize-svc` skeleton in Go: auth → validate → sign → mock APPROVE. Deploy. Real URL.
3. JSON policy schema + deterministic evaluator for the 6 local predicates + explanation.
4. Audit write (async) + signed decisions + tamper test.
5. Python SDK + shadow mode. Put it in front of one design partner in log-only mode.

Everything past step 5 is P1+. Determinism, signing, and audit are the non-negotiable core — get those provably right before breadth.

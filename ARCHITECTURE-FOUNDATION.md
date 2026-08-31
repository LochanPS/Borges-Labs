# AI Transaction Authorization Infrastructure — Architecture Foundation

**Purpose of this document:** Canonical decision base. Every major architectural decision is made and justified here in compressed form. A follow-up model (Opus 4.8) expands each section into full blueprint chapters (PRD, API spec, schemas, diagrams) WITHOUT re-litigating decisions marked `DECIDED`. Items marked `OPEN` require customer discovery. Items marked `CHALLENGE` are pushbacks against the Founder's Context Document that must be resolved by the founder.

Source of truth for company identity: Founder's Context Document v0.1 (Parts 1–2). This document does not change mission, scope, or identity.

---

## 0. Critical challenges to founder doc (resolve before building)

1. **CHALLENGE — Enforcement gap (biggest weakness).** "If rejected, payment never reaches the processor" only holds if the integration is honest. A compromised or buggy agent can simply skip calling our API. Advisory middleware ≠ trust infrastructure. Mitigation path (decided into architecture): every APPROVE returns a **short-lived signed decision token (JWT, ES256)** binding amount + currency + counterparty + agent + expiry. Customer's payment execution layer verifies token claims match the actual payment before executing. Long-term moat: payment providers/issuers verify tokens natively (network effect). MVP ships tokens even if nobody verifies them yet — the contract must exist from v1.
2. **CHALLENGE — "Stateless" vs spending limits.** Cumulative budgets, velocity rules, and monthly limits are inherently stateful. Correct framing: **stateless compute, stateful data plane** (counters). Also requires two-phase spend semantics: authorize = budget **reserve**; confirm/void endpoints release or commit. Without void, failed payments leak budget permanently.
3. **CHALLENGE — "Deterministic" needs precise definition.** Time-based and velocity rules mean same request at different times → different decision. Correct guarantee: *same request + same policy version + same counter snapshot → same decision*. Every decision record stores the policy version and counter snapshot so any decision is **replayable**. This is the auditability story enterprises buy.
4. **CHALLENGE — REVIEW must be in the v1 API contract.** Even if the review workflow ships later, the decision enum `approve | deny | review` must exist day one; adding an enum value later breaks every customer's integration. MVP behavior: `review` maps to deny-with-reason unless customer registers a webhook.
5. **CHALLENGE — Latency promise.** "Milliseconds" globally is physics-impossible over WAN. Promise: **p50 < 10 ms, p99 < 50 ms server-side, regional**. Publish a live latency/status page (trust marketing).
6. **CHALLENGE — Availability = existential.** Inline in the payment path means our downtime halts customer payments. Target 99.99% from GA. Fail-open vs fail-closed must be **customer-configurable per policy** with fail-closed default (see §12 failure modes).
7. **CHALLENGE — Agent-provided context is untrusted.** Justification text, task IDs, etc. come from a possibly prompt-injected agent. Policies must never grant authority based on free-text fields; only on verified identifiers (agent ID from API key, amounts, registered counterparties).
8. **CHALLENGE — Buyer mismatch coming.** Engineering buys v1, but finance/controllers own spend policy. Policies-as-JSON fine for design partners; roadmap must reach non-technical policy authoring by Y2 or deals stall at CFO.
9. **CHALLENGE — Protocol commoditization risk.** AP2 (Google Agent Payments Protocol), Visa Intelligent Commerce, Mastercard Agent Pay are standardizing agent-initiated payments. Position: we are the **policy/decision layer above these protocols**, not a competing rail. Integrate with them; don't ignore them.

---

## 1. Executive summary (DECIDED)

- Product: vendor-agnostic authorization API sitting between AI agents and payment providers. Returns `approve | deny | review` + structured explanation + signed decision token, in <50 ms p99.
- Two planes, two deployables:
  - **Decision plane** (hot path): stateless authorize service, in-memory compiled policy bundles, Redis counters, async audit write. Extreme availability/latency requirements.
  - **Control plane**: policy CRUD, tenants, keys, audit query, dashboard, webhooks. Normal SaaS requirements. Can be down without stopping decisions.
- Modular monolith per plane. No microservices at MVP. Split only when team size or scaling forces it.
- Stack: **Go** for both planes (latency, deploy simplicity, team hiring; Rust reserved for evaluator core if ever needed). PostgreSQL + Redis. No Kafka at MVP (Postgres outbox). Cloud: AWS, single region, multi-AZ.

```
AI Agent ──POST /v1/authorize──▶ [Edge: TLS, authN, rate-limit]
                                        │
                                 Decision Plane (stateless pods)
                                  ├─ validate + idempotency (Redis)
                                  ├─ policy bundle (in-memory, versioned)
                                  ├─ static rules eval
                                  ├─ stateful rules eval (Redis atomic reserve)
                                  ├─ sign decision token
                                  └─ async decision record → outbox → Postgres audit
                                        │
                        approve/deny/review + reasons + token
                                        ▼
                         Customer's payment provider (verifies token claims)
```

Policy bundle distribution: control plane compiles tenant policies → versioned immutable bundle → pushed to decision pods (long-poll/stream). Decision pods never query Postgres on the hot path.

---

## 2. Authorization model (DECIDED)

- Decision = f(request, policy_bundle_version, counter_snapshot). Default **deny** (no matching permit → deny). Explicit `forbid` overrides any `permit` (Cedar semantics).
- Two-phase spend: `POST /v1/authorize` reserves budget; `POST /v1/authorizations/{id}/confirm` commits; `/void` releases. Auto-void on token expiry (default 15 min, configurable).
- Every decision: `decision_id`, reasons[], policy version, counter snapshot, signed token (on approve).
- **Shadow mode** (DECIDED, in MVP): per-agent or per-tenant flag — evaluate + log, never block. Killer adoption feature: customers see what would have been denied before going live.

## 3. Policy engine (DECIDED)

Compared: JSON rules + custom evaluator / custom DSL / OPA-Rego / Cedar.

| | Custom typed JSON rules | OPA/Rego | Cedar | Custom DSL |
|---|---|---|---|---|
| Aggregate rules (budgets, velocity) | native, first-class | bolt-on, awkward | not supported | possible |
| Explainability (rule→reason 1:1) | perfect | poor | good | good |
| Non-technical authoring path (UI later) | easy (data, not code) | hard | medium | hard |
| Determinism/analyzability | by construction | mostly | formally verified | depends |
| Build cost | medium | low | low | high |
| Latency | best (compiled in-proc) | good | best | best |

**Decision: custom typed policy-as-data model** (JSON schema, versioned), compiled to in-memory evaluator; borrow Cedar semantics (default-deny, forbid-overrides-permit, total ordering, no Turing completeness). Rationale: financial policy is aggregate-heavy (limits/budgets/velocity) — neither OPA nor Cedar handles stateful aggregates natively; explanations must map 1:1 to rules; policies-as-data enables the future finance-user UI. Rule types v1: spend limit (per-txn / cumulative per window), vendor allow/blocklist, category restriction, currency/geo restriction, time window, agent permission scope, amount threshold → review. Engine modular: new rule type = new evaluator module + schema, no redesign.

## 4. Explainability (DECIDED)

Structured reasons array, machine-first:
```json
{"decision":"deny","reasons":[{"code":"CUMULATIVE_LIMIT_EXCEEDED","rule_id":"rul_eng_monthly","policy_id":"pol_engineering","message":"Monthly engineering budget $5,000.00 would be exceeded","evidence":{"limit":500000,"spent":487000,"reserved":8000,"requested":12999,"window":"2026-07"}}]}
```
Stable reason codes (documented enum), human message generated from template, evidence = exact numbers used. Approvals also carry reasons (which permits matched). Decisions replayable from stored snapshot.

## 5. API design (DECIDED — expand into full spec later)

- REST, JSON, versioned path `/v1/`. API-first; SDKs wrap.
- Core: `POST /v1/authorize` (idempotency-key header required), `POST /v1/authorizations/{id}/confirm|/void`, `GET /v1/authorizations/{id}`.
- Policy CRUD: `GET/PUT /v1/policies…` (versioned; every change creates immutable version + audit entry).
- Agents: `POST /v1/agents` (register → `agt_` id; keys scoped per agent).
- Audit: `GET /v1/decisions?filter…`, webhook endpoints for decision events.
- Health: `/healthz`, `/readyz`; public status page.
- Request shape (canonical):
```json
{
  "agent_id": "agt_01H…",
  "transaction": {
    "type": "card_payment",
    "amount": {"value": 12999, "currency": "USD"},
    "counterparty": {"id": "vnd_datadog", "name": "Datadog", "category": "saas"},
    "payment_method": {"type": "virtual_card"}
  },
  "context": {"task_id": "…", "human_originator": "a@corp.com", "justification": "…"}
}
```
`context.*` is untrusted metadata — logged, never policy-authoritative (see challenge 7).

## 6. AuthN & security (DECIDED)

- MVP: API keys (per-agent scoped, `sk_live_/sk_test_`, stored hashed, prefix-lookup), TLS 1.3 only. Enterprise later: OAuth2 client-credentials + optional mTLS.
- Replay: idempotency keys + token expiry; optional HMAC request signing (enterprise).
- Rate limiting per key (Redis token bucket). Strict schema validation, minor-units integers only (never floats for money).
- Decision tokens: ES256 JWT, kid-based rotation, JWKS endpoint published.
- Secrets: cloud KMS; no card data ever accepted (keep PCI scope at zero — reject PAN-shaped input).
- Multi-tenant isolation: tenant_id on every row + Postgres RLS.
- SOC 2 Type II track starts at GA — enterprise gate.

## 7. Data model (DECIDED — core entities; expand to full DDL later)

`organizations` → `agents` → `api_keys`; `policies` → `policy_versions` (immutable JSON) → compiled `bundles`; `decisions` (append-only, partitioned by month: request payload, decision, reasons, bundle_version, counter_snapshot, latency); `counters` (authoritative rebuild source = decision log; live copy in Redis); `idempotency_keys` (Redis, 24 h TTL). Indexes: decisions(org, created_at), decisions(agent_id, created_at), key-prefix lookup.

## 8. Storage (DECIDED)

- **PostgreSQL**: everything durable (tenants, policies, audit). Boring, correct, one system to operate.
- **Redis**: counters (atomic Lua reserve/commit), idempotency, rate limits, key cache. Loss tolerated: counters rebuilt from decision log (bounded staleness accepted, documented; enterprise option later: serializable Postgres counters at higher latency).
- Audit at scale (Y2+): partitions → object storage + ClickHouse for analytics. Not MVP.
- Document DB / event store: rejected — no need Postgres JSONB doesn't cover.

## 9. Events (DECIDED)

MVP: **synchronous API + Postgres outbox** → worker → webhooks + audit projections. No broker. Kafka/RabbitMQ/NATS compared: all operational overhead unjustified below ~1k decisions/sec. Adopt **NATS JetStream** when outbox worker lags or self-host gateway needs streaming; Kafka only at large-enterprise scale. Outbox interface designed so swap is internal.

## 10. Deployment (DECIDED)

- MVP: AWS single region, multi-AZ, ECS or EKS (choose EKS only if team already fluent; otherwise ECS Fargate — less ops). Terraform from day one. Everything ships as containers.
- Decision plane image is self-contained (policy bundle + Redis + local buffer) → same artifact becomes the **self-host/enterprise gateway** later (Y2). Deployment-agnostic engine per founder doc.
- Multi-region (Y2–3): tenant home-region pinning; counters are region-local (document constraint — cross-region budget coherence is the hard problem, defer).

## 11. NFR targets (DECIDED)

| | MVP | GA | Y3 |
|---|---|---|---|
| Latency p99 (server, regional) | <100 ms | <50 ms | <25 ms |
| Availability (decision plane) | 99.9% | 99.99% | 99.99% multi-region |
| Throughput | 100 rps | 1k rps | 10k+ rps horizontal |
| Time-to-first-decision (DX) | <30 min from signup | <15 min | — |

## 12. Failure modes (DECIDED)

| Failure | Behavior |
|---|---|
| Control plane down | Decisions unaffected (bundles cached in decision pods) |
| Postgres down | Decisions continue; audit buffered to local disk/queue, flushed on recovery |
| Redis down | Static rules still evaluate; stateful rules per-policy fallback: **fail-closed default**, or customer-configured "approve under $X with `DEGRADED` flag in reasons" |
| Decision plane unreachable | Customer-side choice, documented in SDK: fail-closed (default) or fail-open with local static limit. Never silently fail-open. |
| Bad policy deploy | Immutable versions + one-click rollback + pre-deploy simulation against recent decision log |

## 13. Observability (DECIDED)

OpenTelemetry traces (per-decision trace ID returned in response header), structured JSON logs, Prometheus metrics (decision latency histogram, decision mix, rule hit rates, counter contention), customer-facing decision explorer + webhooks. Every decision traceable end-to-end — first-class product feature, not ops plumbing.

## 14. Testing (DECIDED)

Golden decision suite (policy fixture + request → expected decision + reasons) as the contract; property tests for evaluator determinism; **shadow replay** — re-run production decision log against new engine build, diff decisions, block release on unexplained diffs (this is the killer regression tool); SDK contract tests against recorded API fixtures; k6 load tests with latency SLO gates in CI; chaos: kill Redis, partition AZ; fuzz policy parser.

## 15. Threat model (top items; expand later)

Bypass (→ decision tokens, challenge 1) · TOCTOU: approved $500/vendor-A, agent executes $5,000/vendor-B (→ token binds amount+counterparty; customer/processor verifies) · prompt-injected context fields (→ challenge 7) · stolen API key (→ per-agent scoping, velocity anomaly alerts, instant revoke) · policy tampering (→ immutable versions, admin audit, RBAC) · cross-tenant leakage (→ RLS + tests) · DoS (→ rate limits, autoscale) · replay (→ idempotency + token expiry).

## 16. SDKs & DX (DECIDED)

- Order: **TypeScript, Python** (agent developers live there), Go later. Thin wrappers over REST; generated from OpenAPI + handwritten ergonomics layer.
- Also ship: **MCP tool wrapper** + LangChain/CrewAI middleware adapters — cheap distribution wedge, not scope creep (they just call the API).
- Docs: curl-first quickstart, sandbox tenant with prebuilt policies, policy cookbook, decision explorer. Onboarding goal: first decision in <30 min.

## 17. GTM (DECIDED direction)

3–5 design partners (fintech agent startups, AI accounting platforms), free, white-glove, shadow-mode-first rollout. Public latency/status page. Open-source SDKs + adapters. SOC 2 before enterprise motion. First integrations: Stripe-adjacent stacks (most common in target segment) — but integration = docs/examples, product stays provider-agnostic.

## 18. Pricing (DECIDED direction, validate)

Compared per-request / per-seat / per-agent / tiered / %-of-spend. **Decision: tiered platform subscription bundling decision volume**, enterprise custom on top. Per-seat nonsensical (users are agents). %-of-spend rejected — misaligns incentives, repositions us as payments company. Pure per-request creates adoption friction (metering anxiety). Price points = OPEN, validate with design partners.

## 19. Competitive landscape (positioning)

- AuthZ infra (Oso, Permit.io, OPA/Styra, Cedar/AVP): permissions, not financial transactions, no aggregates/two-phase spend.
- Card controls (Stripe Issuing, Lithic, Ramp/Brex): enforcement but processor-locked, not vendor-agnostic, not agent-aware.
- Fraud (Sift, Forter): probabilistic, post-hoc, human-fraud focused. We are deterministic, pre-execution, policy-driven.
- Agentic payment protocols/startups (AP2, Mastercard Agent Pay, Visa IC, Skyfire, Payman, Catena): rails and identity — we are the policy decision layer above; integrate.
- Differentiation sentence: *deterministic, explainable, vendor-agnostic authorization decision for every agent-initiated transaction, before execution.*

## 20. Moat ranking (DECIDED assessment)

1. **Enforcement network** — decision tokens verified by processors/issuers (strongest, Y3+).
2. **Audit & replay corpus + compliance trust** (SOC2, deterministic replay) — enterprise lock-in.
3. **Policy engine expressiveness** for agent-finance domain.
4. Integration breadth. — Latency and DX are table stakes, not moats.

## 21. Technical debt accepted at MVP (with exit path)

Single region (→ multi-region Y2–3) · audit in Postgres (→ ClickHouse/object storage) · API-key-only auth (→ OAuth2/mTLS) · JSON-only policy authoring (→ dashboard UI Y2) · eventually-consistent counters (→ optional serializable tier) · manual onboarding (→ self-serve) · REVIEW enum present but workflow stubbed (→ approval workflows Y2).

## 22. Roadmap (DECIDED ordering)

- **Y1:** authorize/confirm/void API, policy engine (6 rule types), shadow mode, decision log + explorer, TS/Py SDKs, MCP adapter, 3–5 design partners, 99.9%.
- **Y2:** REVIEW workflows (human approval), dashboard + non-technical policy UI, SOC 2 Type II, self-host gateway, webhooks/streaming, 99.99%.
- **Y3:** multi-region, protocol integrations (AP2 etc.), processor-side token verification pilots, policy simulation/analytics.
- **Y4:** multi-agent delegation chains (agent A delegates budget to agent B), advanced governance.
- **Y5:** industry-standard decision token, ecosystem/policy-pack marketplace, agent identity federation.

## 23. OPEN questions (customer discovery — do not invent answers)

1. Will customers accept a cloud inline dependency in the payment path, or demand self-host from day one?
2. What latency is actually acceptable end-to-end for their flows?
3. Who authors policies at design partners — engineers or finance?
4. Is REVIEW (human-in-loop) required for first deals or genuinely deferrable?
5. Which transaction types dominate real agent spend today (cards vs invoices vs API credits)?
6. Willingness to pay / price anchor per 1k decisions?
7. Will any processor/issuer agree to verify decision tokens (moat #1 validation)?
8. Regulatory classification of inline authorization middleware (not a money transmitter — no funds touched — but get legal opinion before enterprise deals).

---

**Instructions for the expanding model (Opus 4.8):** Expand each numbered section into full blueprint chapters (schemas, sequence diagrams, OpenAPI, DDL, runbooks) one section at a time on request. Treat `DECIDED` as settled unless new customer evidence contradicts. Never expand scope beyond authorization. Keep founder doc as identity source of truth.

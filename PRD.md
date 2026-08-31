# Product Requirements Document — AI Transaction Authorization Infrastructure

*Canonical identity: **Trust Infrastructure for Autonomous Financial Agents**. First product: an authorization middleware that returns a deterministic APPROVE / DENY / REVIEW decision for an AI-initiated financial transaction **before** it reaches the payment provider. The platform never moves, holds, or settles money.*

Status: **Planning / v0.1**. Companion: [TRD.md](TRD.md). Source of truth: Founder's Context Document v0.1.

---

## 0. Reconciliation Note (read first)

This project has two framings in the repo. They are now ordered:

- **Canonical (this doc + Founder's Context Doc):** *Authorization Infrastructure* — a vendor-neutral, framework-neutral decision layer. Deterministic, explainable, low-latency. Positioned like **Auth0 / OPA / Cedar for AI-initiated payments**. This is the company.
- **Subordinate (`PRODUCT-LINE-PLAN.md`, ComplianceAPI/RemittanceRail):** a **concrete vertical** — a sanctions + spend + jurisdiction **policy pack** that runs *on top of* this engine, plus a testnet remittance demo. It is a go-to-market wedge and a hackathon proof, **not a separate company**. Sanctions screening is one policy predicate among many, not the mission.

Where the two conflict, this document wins. The earlier plan's Python/FastAPI, blockchain, and remittance specifics are demo-tier; the company's hot path is Go (see [TRD §4](TRD.md)).

**One challenge up front:** "compliance" and "authorization" are different products with different buyers. The Founder's Doc explicitly says *not compliance software*. Keep the mission as **authorization** (does this agent have the delegated authority to do this?), and treat sanctions/AML as *one policy type customers can enable*, not the headline. Leading with "compliance" invites comparison to Chainalysis/Elliptic and a worse, crowded market. Leading with "authorization for agents" owns a category.

---

## 1. Executive Summary

Autonomous agents are being handed spending authority faster than the controls to govern it exist. Payment rails answer "*can* this payment be processed?" Nobody answers "*should this agent be allowed to make it?*" That question is deterministic, policy-driven, and must be answered inline in milliseconds — which is exactly what an authorization layer is for, and exactly what payment processors and LLMs are structurally bad at.

**Recommended shape:** a two-plane system.
- **Decision plane** — a stateless, horizontally-scaled, Go-based evaluator that takes a signed authorization request, evaluates a compiled policy bundle, and returns a signed decision + structured explanation. Hot path, sub-10ms p99 for local predicates.
- **Control plane** — policy authoring, versioning, key management, audit store, dashboards. Not latency-critical; can be Python/Node.

The one architectural bet that makes this fundable rather than fragile: **decisions are evaluated against a compiled, versioned policy bundle that can run centrally (MVP) or be pushed to a sidecar/SDK at the customer's edge (production).** This decouples your uptime and latency from every single transaction — the OPA/Cloudflare model — and is the difference between "our outage stops your payments" and "our outage is invisible." See [TRD §8](TRD.md) (decision tokens) and [TRD §21](TRD.md) (failure modes).

---

## 2. Goals & Non-Goals

**Goals (v1)**
- Return a deterministic, explainable APPROVE / DENY decision for an agent-initiated transaction in **< 30ms p99** for policy-local evaluation.
- Let an organization define financial policies as data (limits, allow/blocklists, budgets, delegated authority) without code changes.
- Produce a tamper-evident, queryable audit trail of every decision and the exact policy version that produced it.
- Integrate with **one API call**, before the customer's existing payment provider, changing nothing downstream.
- Be provably vendor- and framework-agnostic.

**Non-Goals (v1) — reinforce the mission by refusing these**
- Not moving, holding, or settling funds. Not a PSP, bank, or wallet.
- Not fraud/anomaly detection (probabilistic scoring is a different product; keep decisions deterministic).
- Not a KYC/AML compliance suite (sanctions screening is an *optional enrichment*, not the product).
- Not an agent framework, ERP, accounting system, or identity provider.
- Not a human governance dashboard beyond the audit/review needed to trust decisions.
- **REVIEW workflows are minimal in v1** (return the verdict; the human-approval queue is v1.5). Approve/Deny first.

---

## 3. Personas & User Stories

| Persona | Role | Cares about |
|---|---|---|
| **Integrating engineer** (primary user) | Backend/platform eng wiring the agent to payments | 10-min integration, clear schemas, great errors, SDKs |
| **Policy owner** (buyer-adjacent) | Head of Platform / Eng leadership / CISO | Expressing org rules safely, seeing why a decision happened, audit for their auditors |
| **The agent** (subject, not a user) | Autonomous system | Gets a fast, deterministic yes/no it can act on |

**User stories (v1)**
- *As an integrating engineer,* I POST a transaction to `/v1/authorize` before calling Stripe and get APPROVE/DENY + reason in one round trip, so I gate execution with three lines of code.
- *As a policy owner,* I set "procurement-agent may spend ≤ $5,000/tx, ≤ $50k/month, only to vendors on the allowlist" without deploying code, and every breach is denied with a citation to the exact rule.
- *As a policy owner,* I pull the audit record for any decision and see the inputs, the matched rule, the policy version hash, and the timestamp — defensible to an auditor.
- *As an integrating engineer,* when the service is unreachable, my SDK applies the configured fallback (fail-closed by default, or a cached local decision) so my payment path degrades predictably.

---

## 4. Functional Requirements

**Must have (MVP)**
- `POST /v1/authorize` — evaluate a transaction, return APPROVE/DENY + explanation + signed decision id.
- Policy-as-data: spend-per-transaction limit, rolling budget (e.g., monthly), vendor allow/blocklist, agent→permission mapping, currency/jurisdiction restriction, time-of-day restriction.
- Deterministic evaluation: identical input + policy version ⇒ identical output.
- Structured, human-readable explanation on every decision.
- Signed decision object (verifiable the decision came from us, unmodified).
- Immutable audit log with policy-version hash per decision.
- API-key auth + request signing (HMAC) + replay protection.
- Per-key rate limiting.
- `GET /v1/health`, `GET /v1/audit/{id}`, `GET /v1/audit`, policy CRUD (control plane).

**Should have**
- REVIEW verdict + a basic human-approval queue.
- Policy simulation ("what would this policy have decided against last week's traffic?") — dry-run / shadow mode.
- Stateful budget accumulators with atomic decrement (spend-to-date).
- SDKs (Python, TypeScript first).
- Sanctions/vendor-risk enrichment as an *optional* policy predicate (this is where the ComplianceAPI pack plugs in).

**Nice to have**
- Sidecar/edge policy evaluation for sub-ms local decisions.
- Multi-agent / delegated-authority chains.
- Policy analyzer (prove two policies don't contradict; prove a policy can never approve > $X).

**Future (3–5 yr)**
- Self-hosted + private-cloud + gateway deployments.
- Trust network / reputation across the customer base (data network effect).
- Richer governance analytics, ecosystem integrations, marketplace of policy packs.

---

## 5. Non-Functional Requirements (targets)

| Attribute | MVP target | Production target | Note |
|---|---|---|---|
| Latency (local predicates) | p99 < 50ms | p99 < 10ms | External enrichment (sanctions, budget) breaks this — see below |
| Availability | 99.9% | 99.99% | You are inline; downtime = customer pain. Mitigate with tokens + fallback |
| Determinism | 100% | 100% | No LLM in the decision path. Ever. |
| Auditability | every decision logged w/ policy hash | + tamper-evidence (hash chain) | Legal defensibility is a feature |
| Throughput | few hundred RPS/node | scale horizontally, stateless | Bottleneck is stateful budget checks |
| Explainability | 100% of decisions | 100% | Structured + human-readable |

**Honest tension (challenge to the founder):** "inline + milliseconds + extremely-high-availability + external policy lookups" cannot all be maximal at once. A pure sanctions API call is 100–500ms and can be *down* — that alone blows the latency and availability targets. **Resolution:** split predicates into **local** (limits, allow/blocklists, time — µs, always available) and **enriched** (sanctions, live budget, vendor risk — I/O-bound, can fail). Local predicates give the fast/available guarantee; enriched predicates are explicitly best-effort with a declared fail-open/fail-closed policy. Sell the guarantee only on what you can actually guarantee. Details in [TRD §21](TRD.md).

---

## 6. MVP Definition (the sharp line)

**In:** hosted `POST /v1/authorize`; policy-as-data for the 6 local predicate types; deterministic engine; signed decisions; audit log w/ policy hash; API-key + HMAC auth; rate limiting; health + audit read APIs; a minimal control-plane UI to author policies and read the audit log; Python + TS SDK wrapping the API; shadow mode (log-only) so a design partner can run it against real traffic without blocking payments.

**Out:** REVIEW queue, sidecar/edge eval, self-host, sanctions enrichment (optional add-on, not core MVP), multi-agent chains, billing system, blockchain/remittance.

**MVP success = a design partner runs us in shadow mode against real agent traffic for 2 weeks, then flips to enforce mode on one agent.** That flip is the whole validation.

---

## 7. Success Metrics

- **Activation:** time from API key to first `authorize` call < 15 min.
- **Adoption depth:** % of design partners who move from shadow → enforce mode.
- **Trust:** decisions with a complete, correct explanation = 100%; audit records retrievable = 100%.
- **Performance:** p99 local-decision latency; enrichment timeout rate.
- **Commercial:** design partners → paying; decisions/month per customer (usage = value proxy).

---

## 8. Pricing (recommendation)

| Model | Fit | Verdict |
|---|---|---|
| Per authorization request | Aligns cost to value; scales with agent activity; Twilio/Stripe-familiar | **Recommended** primary meter |
| Per agent | Simple, but agents are cheap to spawn; gameable | Secondary/enterprise floor |
| Per seat | Mismatched — buyers are machines, not humans | Reject |
| Tiered + enterprise | Package the meter; enterprise adds SLA/self-host | **Yes, on top** |

**Recommend:** usage-based per-decision, packaged into Free / Team / Enterprise tiers; enterprise adds SLA, SSO, self-host, dedicated policy support. Don't build billing infra until 5 paying customers — track decisions in the audit store, invoice manually.

---

## 9. Go-To-Market (technical)

- **First integration pattern:** a 3-line wrapper before the customer's existing payment call, plus a **shadow mode** that logs the decision without blocking. Shadow mode removes all adoption risk — that's the wedge.
- **Design partners:** 3–5 teams already giving agents spend authority (fintech automation, AI-accounting, procurement agents). The ComplianceAPI hackathon list is a valid source.
- **Early-adopter workflow:** key → SDK → shadow mode on one agent → review the audit log together → flip to enforce. The audit log *is* the sales demo.
- **The ComplianceAPI vertical as a beachhead:** ship the sanctions+spend policy pack as a ready-made template so a customer sees value on day one without authoring policies from scratch.

---

## 10. Roadmap (phased)

- **P0 (MVP):** hosted authorize API, local predicates, signed decisions, audit, shadow mode, 2 SDKs.
- **P1:** stateful budgets (atomic accumulators), REVIEW + approval queue, policy simulation, sanctions enrichment pack.
- **P2:** sidecar/edge evaluation (latency + availability leap), self-host, policy analyzer.
- **P3:** multi-agent/delegation chains, trust-network reputation, deployment breadth, policy-pack marketplace.

Full technical sequencing in [TRD §24](TRD.md).

---

## 11. Open Questions (need customer validation — not inventing answers)

- Do buyers want **enforce** inline, or is a signed-audit "assurance" layer the real initial value? (Shadow-mode uptake will tell us.)
- What's the true latency budget customers will tolerate *in the payment path*? 10ms? 100ms?
- Fail-open vs fail-closed default — which do real customers actually want when we're down?
- Is sanctions screening a "must" for early buyers, or a distraction from delegated-authority? (Decides whether the ComplianceAPI pack is core or optional.)
- Will customers accept a **sidecar** (for latency/availability) or demand pure hosted API? Shapes the whole deployment story.
- Regulatory: does sitting inline the payment path (even without moving money) create licensing/liability exposure in any target jurisdiction? **Get a lawyer's read before enforce-mode in production.**

---

## 12. Assumptions Being Bet On (state them, test them)

Facts: payment rails don't answer the authorization question; LLMs are non-deterministic and unfit for the decision path. Hypotheses (validate): orgs will add a middleware layer rather than build in-house; explainability + audit matter as much as the yes/no; a narrow authorization product beats a broad governance platform for adoption. Track each against design-partner behavior.

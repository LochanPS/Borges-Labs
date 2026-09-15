# Product Status & Roadmap to a Full-Scale Product

Honest audit of what is built vs. planned (PRD/TRD/ROADMAP), plus the backlog to take
this from a complete MVP to a YC-scale, self-serve product.

_Last updated: 2026-09-15._

---

## 1. MVP capability audit (PRD §4 must-have / §6 MVP line)

| Capability | Status | Where |
|---|---|---|
| `POST /v1/authorize` + explanation + signed decision | ✅ | authorize-svc |
| Policy-as-data, 6 local predicate types | ✅ | `internal/engine`, `internal/policyctl` |
| Deterministic evaluation (pure fn of req+policy+time+counters) | ✅ | engine + contract |
| Structured, human-readable explanation on every decision | ✅ | `explanation.matched_rules` |
| Ed25519-signed, third-party-verifiable decisions | ✅ | signing + SDK/dashboard verify |
| Immutable audit log w/ policy-version hash + hash chain | ✅ | `internal/audit`, `record_hash` |
| API-key + HMAC request signing + replay protection | ✅ | `internal/auth` |
| Per-key rate limiting | ✅ | `internal/ratelimit` |
| `GET /v1/health`, decisions read API, policy CRUD | ✅ | server + control plane |
| Minimal control-plane UI (author policy, read audit) | ✅ | `services/dashboard` |
| Python + TypeScript SDKs | ✅ | `sdks/python`, `sdks/ts` |
| Shadow mode (log-only) | ✅ | per-key `shadow`, advisory-first |

**Should-have (PRD §4):**

| Capability | Status | Note |
|---|---|---|
| Policy simulation (dry-run vs. traffic) | ✅ | `POST /v1/policies/{id}/simulate` |
| Stateful budget accumulators, atomic | ✅ | two-phase holds, Redis counters (Task 3.2) |
| REVIEW verdict | ✅ (verdict) / ❌ (queue) | engine emits REVIEW; **no human-approval queue** |
| Sanctions/vendor-risk enrichment | ❌ | predicate types are schema placeholders only |

**Beyond MVP, added this cycle:** `GET /v1/policies` (list), full API-key management
(create/list/revoke), security response headers, `/metrics` (Prometheus), OpenTelemetry
tracing, dashboard status page, threat-model + chaos/fail-closed test suites, and
Fly/Railway/Vercel deploy configs + guide.

### Verdict
**The MVP is functionally complete.** Remaining MVP-adjacent gaps are the REVIEW queue
and the (optional, explicitly out-of-MVP) enrichment pack. Everything else below is the
work of turning a complete MVP into a full-scale product.

---

## 2. What a YC-scale product still needs

Grouped by theme, with the gap and the proposed build. Priority: **P0** = needed for
self-serve design partners; **P1** = needed to scale/charge; **P2** = enterprise/moat.

### A. Self-serve onboarding & identity (P0)
The single biggest gap. Today an org and its keys are minted via CLI; Clerk authenticates
dashboard users but is not linked to API-key orgs, and any valid key is effectively org-admin.

- **Org + user model**: map a Clerk user → an org; create an org on first sign-in.
- **RBAC**: roles (owner/admin/developer/viewer); scope key-management + policy-publish to
  admins. (Contract already carries `scopes` on keys — enforce them.)
- **Self-serve signup → first key → first authorize** entirely in the UI (no CLI).
- **"Connect your agent" wizard**: pick language → show the 3-line SDK snippet prefilled
  with a freshly minted **test** key → live-updating "waiting for your first decision…"
  that flips green when traffic arrives. Activation metric (PRD §7: key→authorize <15 min).

### B. Agent management (P0)
Agents exist only as strings inside policies/decisions. Operators need a first-class view.

- **`/agents` dashboard page**: list agents (derived from recent decisions or a registry),
  per-agent verdict mix + spend, and a **shadow → enforce toggle per agent** (the core
  rollout lever, ROADMAP §6.1). _(A derived read-only version ships in this cycle.)_
- **Agent registry** (optional): `POST /v1/agents` so an agent is a managed object with
  an owner/principal, not just a free-form id. Data model already has `principals`+`agents`.

### C. In-product testing (P0) — _shipping this cycle_
- **Playground page**: fire a test authorization from the dashboard, see the decision +
  explanation + one-click signature verify. _(built)_
- **Free demo agent**: a runnable script that simulates an AI agent making a burst of
  transactions (some approve, some deny) through the SDK — `--mock` (no backend) or live.
  _(built: `examples/demo-agent/`)_

### D. Human-in-the-loop: REVIEW queue (P1)
- `POST /v1/authorize` already yields REVIEW. Add an approvals store + endpoints
  (`GET /v1/reviews`, `POST /v1/reviews/{id}/approve|deny`) and a dashboard queue so a
  human can clear step-ups. Wire step-up obligations into the decision.

### E. Enrichment pack (P1, optional)
- Implement the enriched predicate types (`sanctions_screen`, `vendor_risk`) with a
  timeout-bounded, fail-policy-governed adapter (TRD §21). Ship the ComplianceAPI
  sanctions+spend+jurisdiction **policy pack** template so a customer sees value day one.

### F. Notifications & webhooks (P1)
- Outbound **webhooks** on DENY/REVIEW, budget threshold crossed, key created/revoked,
  enrichment degraded. Signed payloads (reuse Ed25519). Retries + dead-letter.
- Email/Slack alerts for operators.

### G. Metering & billing (P1)
- Surface **usage** (decisions/month per org/agent) in the dashboard (data already in the
  audit store). Then Stripe metered billing + Free/Team/Enterprise tiers (PRD §8). Defer
  the billing integration until ~5 paying customers, but ship the usage view now.

### H. Reliability & ops (P1)
- **Prometheus alert rules** (latency SLO burn, enrichment 5-consecutive-fail, rate-limit
  spikes) + **Sentry** error tracking + a **public status page**.
- **Load test** harness (k6) to prove p99 under target RPS (TRD §19); chaos already covered.
- Backups/PITR for Postgres; runbooks.

### I. Developer experience (P1)
- **Go and Java SDKs** (Go types already generated in `contracts/gen/go`).
- **CLI** (`azn`): create key, tail decisions, run a simulation, verify a receipt.
- **Audit export** (CSV/NDJSON) and full-text decision search/filters in the dashboard.
- Guided **policy rule builder** (no raw JSON) for non-engineers.

### J. Enterprise & moat (P2)
- **SSO/SAML** + SCIM; **audit trail of control-plane actions** (who changed a policy).
- **Self-host / VPC** + **sidecar/edge** evaluation (TRD §8, sub-ms local decisions).
- **Multi-agent / delegated-authority chains**; **policy analyzer** (prove a policy can
  never approve > $X); **policy-pack marketplace**; **trust-network reputation**.
- **SOC 2 Type II**, data-residency regions, DPA.

---

## 3. Recommended sequence (next 6 milestones)

1. **M1 — Self-serve onboarding**: org/user model + RBAC + signup + "connect your agent"
   wizard. Unblocks design partners without hand-holding. _(P0)_
   - **In progress:** org bootstrap endpoint `POST /v1/provision/keys` (platform-token
     auth, mints a new org's first key); dashboard RBAC (owner/admin/developer/viewer,
     Clerk-or-dev identity, admin-gated mutations); `/onboarding` connect-your-agent
     wizard (create key → SDK snippet → run). **Remaining (M1b):** map each Clerk org to
     its own provisioned key so the dashboard calls authorize-svc per-org (needs a small
     dashboard datastore) instead of one shared admin key.
2. **M2 — Agent management + usage view**: `/agents` with per-agent enforce toggle; usage
   metering surfaced. _(P0/P1)_
3. **M3 — REVIEW queue**: approvals endpoints + dashboard queue. _(P1)_
4. **M4 — Webhooks + alerts + Sentry + status page + k6 load test**. _(P1)_
5. **M5 — Enrichment pack + ComplianceAPI template**. _(P1)_
6. **M6 — Billing (Stripe) + Go/Java SDKs + CLI**. _(P1/P2)_

Enterprise (SSO, self-host, sidecar, analyzer, marketplace) follows customer pull.

---

## 4. How to verify the product today (free)

- **In the dashboard**: open **Playground**, fire a test authorization, watch the verdict
  + explanation, click **Verify signature** (validates the Ed25519 receipt in-browser).
- **From the terminal**: run the free demo agent — no backend required:
  ```bash
  cd services/... ; python examples/demo-agent/agent.py            # mock mode
  # or against a running service:
  python examples/demo-agent/agent.py --base-url https://… --api-key azn_test_…
  ```
  It simulates a procurement agent making a stream of transactions and prints each
  APPROVE/DENY/REVIEW with the reason.

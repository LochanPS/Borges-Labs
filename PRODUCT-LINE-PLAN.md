# ComplianceAPI — Product Line & Money Plan

*Canonical, consolidated plan. Supersedes the scattered build-plan drafts, the presentation content, and the video script. One source of truth from here on.*

---

## 0. TL;DR — The Cook in Six Lines

1. This is **not one product. It's a product line with two rails** that feed each other.
2. **Rail 1 — ComplianceAPI:** the pre-flight compliance verdict primitive. B2B infra. Sells to anyone moving money. Legally shippable by a 5-person team **now**.
3. **Rail 2 — RemittanceRail:** a compliant USDC remittance flow built *on top of* Rail 1. It is (a) the killer demo, (b) Rail 1's first and biggest customer, and (c) the venture-scale revenue engine.
4. **Two money engines.** API = thin, sticky, slow ($/call). Remittance = fat, volume-scaling take-rate (% of $ moved). The remittance rail is where the YC story lives.
5. **The fork that decides YC vs Razorpay:** *do you touch the money yourself, or do you sell the primitive to people who are already licensed to touch it?* Operating remittance solo = money-transmitter/RBI licensing = months + capital + legal. Selling the primitive = ship next month.
6. **Recommended path:** build the primitive as the sellable core, use the remittance rail as a testnet demo + design-partner co-build with a *licensed* partner. De-risk the legal, keep the venture upside.

---

## 1. The Product Line

### Rail 1 — ComplianceAPI (the primitive)

One line: *a real-time, pre-flight compliance verdict API for teams building autonomous agent payment pipelines.*

One `POST /v1/check` call. Under 500ms. Returns `PASS | BLOCK | REVIEW | UPSTREAM_UNAVAILABLE` plus a tamper-evident audit receipt — **before** funds move. That's the whole product. Not a dashboard, not monitoring, not fraud detection, not KYC. A synchronous pre-flight gate that sits in the transaction execution path.

```python
r = httpx.post(
    "https://api.complianceapi.dev/v1/check",
    headers={"X-API-Key": "capi_live_abc123"},
    json={
        "wallet_address": "0xAbC...123",
        "amount_usd": 1200.00,
        "agent_id": "procurement-agent-v2",
        "jurisdiction": "US",
        "counterparty_name": "Acme Supplies Ltd"
    },
)
# → {"verdict": "PASS", "audit_id": "aud_01HXYZ...", "checks": {...},
#    "latency_ms": 187, "receipt_url": ".../v1/audit/aud_01HXYZ..."}
```

**Who buys it:** the integrating engineer (primary — judges you on docs + response shape), the compliance officer (economic buyer — needs the audit receipt for regulators), you (ops).

**Why now:** EU AI Act — high-risk autonomous financial AI needs documented, auditable decision trails by **Aug 2, 2026**. ComplianceAPI produces that trail as a byproduct of every call. The deadline is the sales opener.

### Rail 2 — RemittanceRail (the application, built on Rail 1)

One line: *a compliant, sub-1% USDC remittance flow for the $125B India inbound corridor, gated by ComplianceAPI.*

`POST /v1/remittance/send` → maps to the same `TransactionInput` → runs the **full Rail 1 pipeline** → on `PASS`, an ECDSA-signed verdict unlocks the on-chain transfer (Chainlink USD/INR oracle → `RemittanceGateway.sol` → USDC ERC-20 → Basescan-verifiable event). On `BLOCK`, no signature is issued, so the contract **cannot** execute. Enforcement lives at the cryptographic layer, not the app layer — no bypass path.

**Three reasons Rail 2 exists (and why it's not a distraction):**
- **It's the demo.** "Watch a real transfer clear compliance and settle on-chain in one call" beats any slide.
- **It's Rail 1's flagship customer.** Every transfer = compliance calls + audit receipts + real load. You dogfood your own primitive and generate the case study.
- **It's the money.** API pricing is thin. Take-rate on money moved is not (see §2).

### How the rails relate

```
                 ┌─────────────────────────────┐
   agent devs ──▶│  Rail 1: ComplianceAPI      │◀── you sell this to
   (external)    │  the pre-flight primitive   │    licensed money-movers
                 └──────────────┬──────────────┘
                                │ every send = compliance calls
                                │ + audit receipts (dogfood)
                 ┌──────────────▼──────────────┐
                 │  Rail 2: RemittanceRail     │──▶ end users / gig workers
                 │  compliant USDC settlement  │    (transaction revenue)
                 └─────────────────────────────┘
```

Rail 1 is the moat and the sellable primitive. Rail 2 is the volume, the proof, and the venture engine. **Build Rail 1 first — Rail 2 is literally a caller of it.**

---

## 2. Money Model — Two Engines

### Engine A — ComplianceAPI (per-call SaaS)

| Tier | Included/mo | Overage | Base/mo | For |
|---|---|---|---|---|
| Free | 500 | — | $0 | Eval, hackathons. **No credit card.** Email only. |
| Starter | 5,000 | $0.008/call | $29 | Early production |
| Growth | 50,000 | $0.006/call | $199 | Multiple agents |
| Enterprise | custom | custom | custom | SLA, volume discount |

Unit cost ≈ $0.0025/call (OFAC ~$0.001 + sanctions.io ~$0.001 + compute ~$0.0005; Redis/PG negligible). At $0.008 that's ~3x margin — right for early infra.

**Honest ceiling:** to reach $1M ARR on the API *alone*, at ~$0.006 blended you need ≈ 14M calls/month. That's a lot of agent traffic for a young company. Engine A is real, sticky infra — but on its own it's a slow SaaS grind, not a venture rocket. Good enough to be a genuine business and a strong internship-caliber build. Not, by itself, the YC story.

### Engine B — RemittanceRail (take-rate on $ moved) — **the venture engine**

Incumbents on the US→India corridor: banks 5–7%, older MTOs ~6.2% avg. You charge **all-in ~0.9–1.5%** (FX spread + flat fee), still crushing them, because USDC rails + your own compliance layer cut the cost stack.

Take ~1% net of volume:

| Monthly volume settled | Monthly revenue | Annualized |
|---|---|---|
| $1M | $10K | $120K |
| $10M | $100K | $1.2M |
| $100M | $1M | $12M |

Corridor is $125B/yr inbound to India. **0.1% share = $125M/yr volume → ~$1.25M/yr. 1% share → ~$12.5M/yr.** Take-rate scales with **dollars moved**, not API calls — a far steeper curve than Engine A.

### The key insight: B feeds A

Every remittance is: N compliance calls + an audit receipt + real production load on Rail 1. Engine B *is* Engine A's best customer and its live proof. You don't cold-start the API with 20 emails — you cold-start it with your own transaction volume and a real case study.

### MVP money rule (unchanged, correct)

No billing system in code at MVP. No Stripe integration. Track call counts in Postgres, invoice manually / Stripe payment link. **Build the Stripe/metered-billing infra the moment you have 5 paying customers — not before.**

---

## 3. The Regulatory Fork — This Decides YC vs Internship

Be honest with yourself here, because the raw plan hand-waves it and it's the single biggest risk.

**Rail 1 (verdict API) is low legal risk.** You screen and advise. You never hold or move funds. A small team can ship this and sell it.

**Rail 2 (moving money) is high legal risk *if you operate it yourself*.** Real US→India remittance means: money-transmitter / MSB registration in the US, RBI authorised-dealer channel + FEMA/LRS compliance in India, KYC/AML obligations, banking partners, and capital. That is months of legal work and money — not an evening build. Testnet + mock ≠ a live money business.

**Two paths:**

- **Path A — Infra-only (ship now, lower ceiling).** Sell the ComplianceAPI primitive to companies that are *already licensed* to move money — fintechs, PSPs, remittance providers, neobanks, authorised-dealer banks. You're picks-and-shovels. Fully shippable by your team. This is the safe, Razorpay-internship-strong, genuine-business path.

- **Path B — Operate the remittance rail (venture prize, gated).** You run RemittanceRail as a product. This is the $12M/yr curve — but it requires the licensing above, or a **licensed partner** (BaaS / authorised dealer / licensed MTO) who holds the license while you provide the tech + compliance layer and share the take-rate.

**Recommendation:** don't become an unlicensed money transmitter to win a hackathon. Do this:
1. Build **Rail 1** as the sellable, de-risked core.
2. Ship **Rail 2 on testnet (Base Sepolia)** as the flagship demo — real code, real on-chain settlement, zero regulated fiat. Perfect for the hackathon and YC application.
3. For real volume, pursue Rail 2 **through a licensed partner**, not solo. That partner conversation *is* your first serious business development.

This keeps the venture upside (Path B narrative) while staying legally shippable (Path A reality). That's the cook.

---

## 4. What You're Building — Consolidated Architecture

Three layers. Build top-down; the last is for you alone.

```
LAYER 1 — PUBLIC API      the product. fast, versioned, reliable.  (Rail 1 + Rail 2 endpoints)
LAYER 2 — DASHBOARD       audit viewer, keys, usage. compliance officers + owners.
LAYER 3 — INTERNAL OPS    upstream health, customer view, key/limit status. you only. build last.
```

**Backend:** Python 3.11, FastAPI, async throughout. PostgreSQL via SQLAlchemy async. Redis (rate limiting + 5-min API-key lookup cache). **Async audit writes via FastAPI `BackgroundTasks` at MVP** — response returns before the audit row is written; upgrade to Celery only when traffic justifies it. *(Resolves the BackgroundTasks-vs-Celery contradiction in the source: BackgroundTasks for MVP.)*

**Blockchain (Rail 2, testnet MVP):** Solidity ^0.8.20, Hardhat, OpenZeppelin v5, Base Sepolia. `RemittanceGateway.sol` (~60 lines) verifies an ECDSA signature from the compliance engine before executing a USDC ERC-20 transfer; emits a Basescan event as on-chain audit proof. Contract is upgradable without redeployment.

**Upstream compliance sources:**
- OFAC SDN — ofac-api.com (free tier, wallet + name screening).
- EU + UN sanctions — sanctions.io (free tier, both lists, ~60-min refresh).
- On-chain wallet risk — **mocked at MVP**, documented placeholder (confidence 0). Chainalysis/TRM post-MVP.
- FX (Rail 2) — Chainlink USD/INR oracle → ExchangeRate API fallback → hardcoded rate (three-tier, zero-downtime).

**Frontend:** Next.js + TypeScript, Tailwind, shadcn/ui, Recharts, ethers.js v6. Clerk auth. Deploy Vercel. Docs auto-generated from the FastAPI OpenAPI spec (Scalar/Redocly) — never handwritten.

**Infra:** Railway (FastAPI + Postgres + Redis plugins, auto-deploy on main). Vercel (frontend). Sentry (errors). Instatus/BetterUptime (status page polling `/v1/health` every 2 min). Domain `complianceapi.dev` → `api.` / `app.` / `docs.`. Secrets in Railway/Vercel env, never in git. **No** Kubernetes / LB / CDN / multi-region at MVP.

---

## 5. The Compliance Pipeline — Canonical (5 Checks)

On `/v1/check`, exact internal order. Local checks are cheap and run first (short-circuit); upstream calls run **concurrently** via `asyncio.gather`.

| # | Step | Target | Notes |
|---|---|---|---|
| 1 | **Auth** | <5ms | SHA-256 the key. Redis lookup → PG on miss (5-min TTL). `hmac.compare_digest`, never `==`. 401/403 on fail. |
| 2 | **Validation** | <2ms | Pydantic v2. EVM checksum via `Web3.is_checksum_address`. Strict regex on `agent_id`, `jurisdiction` (ISO-3166-1 alpha-2), `counterparty_name`. Reject bodies >8KB. |
| 3 | **Rate limit** | <5ms | Redis sliding window per key, atomic `INCR`+`EXPIRE`. 429 + `Retry-After`. |
| 4 | **Compliance checks** | <300ms | Run concurrently — latency = slowest upstream, not sum. |
| 5 | **Verdict assembly** | <5ms | Any BLOCK → BLOCK. Any REVIEW (else all clear) → REVIEW. All clear → PASS. Any upstream failure → UPSTREAM_UNAVAILABLE. |
| 6 | **Response** | immediate | Return before audit write. |
| 7 | **Async audit write** | background | `BackgroundTasks` → compute record hash → write PG. Decoupled from response latency. |

**The five checks (Step 4):**
1. **Sanctions** — OFAC SDN + EU + UN, fuzzy match (rapidfuzz — "Mohammed Al-Rashid" ≈ "Muhammed Alrasheed"). ~5ms.
2. **Spend policy** — local. Per-key/customer limits + GIG-TIER (KYC tier 0/1/2) counters in Redis. `WITHIN_LIMIT | EXCEEDED`. ~8ms.
3. **Jurisdiction** — local. OFAC embargo codes + allowed/blocked lists + FATF grey-list flag. `COMPLIANT | BLOCKED`. ~2ms.
4. **RBI/FEMA rules (India corridor)** — local. LRS annual cap (₹7 lakh) via Redis counter (400-day TTL, no cron), monthly counter (32-day TTL), purpose-code validation against the real RBI Form A2 list, KYC tier gating. ~12ms.
5. **On-chain wallet risk** — mocked at MVP (documented placeholder). Post-MVP: Chainalysis KYT.

**Verdict truth table — every one of these is an explicit, passing unit test (100% branch coverage on assembly, non-negotiable):**
```
OFAC BLOCK,  EU CLEAR,  UN CLEAR                     → BLOCK
OFAC CLEAR,  EU BLOCK,  UN CLEAR                     → BLOCK
OFAC CLEAR,  EU CLEAR,  UN CLEAR, spend EXCEEDED     → BLOCK
OFAC CLEAR,  EU CLEAR,  UN CLEAR, jurisdiction BLOCK → BLOCK
OFAC REVIEW(0.65), EU CLEAR, UN CLEAR                → REVIEW
OFAC CLEAR,  EU CLEAR,  UN CLEAR, spend WITHIN_LIMIT → PASS
OFAC TIMEOUT, EU CLEAR, UN CLEAR                     → UPSTREAM_UNAVAILABLE
```

---

## 6. Failure Handling & Security — Canonical

### Fail closed. Never fail open.

A wrong PASS is a legal liability. If a check can't complete, you do **not** return PASS.

- **Single upstream timeout/5xx:** 2s timeout each (OFAC, sanctions.io). Retry once after 500ms. Still failing → mark that check `UPSTREAM_TIMEOUT`/`UPSTREAM_ERROR`.
- **Any check failed → overall `UPSTREAM_UNAVAILABLE`, HTTP 503**, RFC-7807 body listing `checks_completed` and `checks_failed`, plus `retry_after`. The caller holds the transaction with full information. Audit record for the incomplete check is still written.
- **All upstreams down:** 503, same shape, log immediately (it's your network, not one vendor).
- **Sustained (>30 min):** `/v1/health` degraded for 5 consecutive 2-min polls → Sentry alert + status page. Never silently serve 503s for hours.
- **Never:** fake PASS, undisclosed stale sanctions data served as live, or a 500 masking an upstream error.
- **Exception:** jurisdiction + spend + RBI are *your own data* — they can't be "down." Only failure mode is a Postgres outage (your infra problem).

### Security (decisions made before the first endpoint)

- **Keys:** `secrets.token_urlsafe(32)` (256-bit). Store only `sha256(key)`. Plaintext shown once, then gone — revoke-and-reissue only. `capi_live_` / `capi_test_` prefix (not stored; last 6 chars kept for display). Compare with `hmac.compare_digest`.
- **Input:** EVM checksum validation; strict regex on all string fields; reject >8KB bodies at middleware. SQLAlchemy ORM only — never f-string SQL.
- **Rate limiting — 3 layers:** (1) per-key Redis sliding window (Free 10/min, Starter 60, Growth 300); (2) per-IP >100/min throttle at infra level (catches key-stuffing); (3) per-key burst cap 10/sec (second 1-sec Redis counter). At 10K RPS: Railway ingress → IP throttle → Redis 429 absorb the load before your app does.
- **Transport:** HTTPS only (Railway/Vercel TLS). Middleware adds `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, CSP on the dashboard.
- **Never expose:** stack traces, DB errors, internal service names, SQL fragments, upstream keys/URLs, or any field not in the Pydantic response model (FastAPI response-model enforcement handles most of this).

---

## 7. API Surface — Canonical (dedup'd)

All endpoints `/v1/`. Breaking changes → `/v2/`, `/v1/` maintained indefinitely (Stripe rule). Every request: `X-API-Key`. Errors are RFC 7807, no exceptions.

**Rail 1**
- `POST /v1/check` — the core. Request: `wallet_address` (req), `amount_usd` (req, >0), `agent_id` (req), `jurisdiction` (req, ISO-3166-1 α2), `counterparty_name` (opt), `transaction_id` (opt). Response: `verdict`, `audit_id` (ULID), `checks`, `latency_ms`, `timestamp`, `receipt_url`, `blocked_reason`? / `review_reason`?.
- `GET /v1/audit/{audit_id}` — full record + `hash_verified` computed at query time. The regulator receipt.
- `GET /v1/audit` — paginated for the key. Params: `page, limit, verdict, date_from, date_to, agent_id`.
- `GET /v1/health` — public, no auth. Upstream status + `latency_p50_ms` / `latency_p95_ms`.
- `GET /v1/policy` — the key's policy (spend limits, jurisdiction rules). Read-only at MVP.
- `POST /v1/keys` / `DELETE /v1/keys/{key_id}` — dashboard-facing. Plaintext returned once; revoke is immediate.

**Rail 2**
- `POST /v1/remittance/send` — sender details + `amount_usd` + destination. Runs the full `/v1/check` pipeline; on PASS, ECDSA-signs and settles via `RemittanceGateway.sol`. Returns the verdict, the on-chain tx hash, and the audit receipt.

**Status codes:** 200 ok, 400 validation, 401 missing/invalid key, 403 revoked/tier-exceeded, 429 rate-limited, 503 upstream unavailable, 500 internal (never leak).

*(Field-name fix: the source flip-flopped between `wallet` and `wallet_address`. Canonical is `wallet_address` everywhere.)*

---

## 8. Data Model — Canonical (contradictions resolved)

```
customers      id(ULID) · email(unique) · company_name · spend_limit_usd · daily_limit_usd
               · allowed_jurisdictions[] · blocked_jurisdictions[] · kyc_tier · created_at

api_keys       id(ULID) · customer_id(FK) · name · key_hash(unique) · prefix
               · tier(free|starter|growth|enterprise) · is_active · rate_limit_rpm
               · created_at · last_used_at

audit_records  id(ULID, time-sortable) · api_key_id(FK) · wallet_address · amount_usd
               · agent_id · jurisdiction · counterparty_name? · transaction_id?
               · verdict(PASS|BLOCK|REVIEW|UPSTREAM_UNAVAILABLE) · blocked_reason?
               · review_reason? · checks_detail(JSONB) · latency_ms
               · record_hash(sha256 of canonical content) · upstream_versions(JSONB) · created_at

upstream_health_log  id(ULID) · source(ofac|eu_sanctions|un) · status(ok|degraded|down)
                     · latency_ms? · error_detail? · checked_at
```

*(The source had two competing tables — `sanctions_cache` in one draft, `upstream_health_log` in the other. Keep `upstream_health_log` (drives `/v1/health` + monitoring). Sanctions-list caching is a Redis concern with a TTL, not a Postgres table — don't model it as one.)*

Record hash = SHA-256 of canonical record content, computed on write. Verify by rehashing on read. Tamper-evident without a blockchain. (Rail 2 additionally emits the Basescan event as a second, on-chain proof.)

---

## 9. Build Sequence — Hackathon MVP → Sellable → Venture

**Phase 0 — Setup (1 day).** Repo, venv, FastAPI skeleton with `/v1/health` → 200. Postgres + Redis via Docker Compose. Railway linked to GitHub. First deploy live. Real URL before any compliance logic.

**Phase 1 — Rail 1 core (4–5 days).** `/v1/check` with mocked checks (all PASS) first — nail request validation, response shape, error format, key auth. Then replace mocks one by one: spend → jurisdiction → RBI → OFAC → EU/UN. Rate limiting. Async audit write. *End state: real verdict from real sanctions data. This is the product.*

**Phase 2 — Audit layer (2–3 days).** `/v1/audit/{id}`, record hash on write, verify on read, **explicit test that a mutated record fails verification.**

**Phase 3 — Testing (parallel with 1–2, not after).** Unit: verdict assembly (100% branch), spend, jurisdiction, RBI, hash, timing-safe compare, validation. Integration (real test PG in Docker, upstreams mocked): every endpoint, every status code, tamper test, rate-limit test, upstream-timeout→503. Sanctions-accuracy tests against real APIs on PRs only, with a fixture of 5–10 known-sanctioned/known-clean entities. Tools: pytest, pytest-asyncio, pytest-httpx, pytest-cov, httpx.AsyncClient, factory_boy, Docker Compose.

**Phase 4 — Rail 2 demo (3–4 days, testnet).** `RemittanceGateway.sol` on Base Sepolia, ECDSA gating, Chainlink FX + fallbacks, `POST /v1/remittance/send`, live Basescan confirmation. **Testnet only — no regulated fiat.** This is the flagship demo + YC narrative.

**Phase 5 — Dashboard (5–7 days).** Next.js + Clerk. Overview (3 metric cards + upstream dots + 14-day sparkline), audit log (filterable table, 25/page), audit receipt (printable, in-browser hash verify, print-to-PDF), API keys (create-once modal, revoke), usage/billing (progress bar → Typeform upgrade link, no Stripe at MVP).

**Phase 6 — Docs + launch (2 days).** Generated OpenAPI docs, <10-step quickstart, landing page, working "Start Free" path.

**Phase 7 — Customers (from week 3, overlapping).** See §10. Don't wait for polish — get someone calling `/v1/check` before the dashboard exists.

Realistic: **~4 weeks of focused evening work** to a live, usable product with real compliance data + a testnet remittance demo.

---

## 10. GTM — The Remittance Rail *Is* the Go-To-Market

The raw "cold-email 20 engineers" plan is weak on its own. Stronger: **Rail 2 generates the proof that sells Rail 1.**

- **Beachhead you already own:** the Razorpay hackathon prospect list — everyone who built a payment agent there has this exact problem. You have their names. Message them.
- **Signal-based outreach:** GitHub search `x402`, `agent payments`, `USDC payment agent`, recent commits → the person who committed last week is actively building. Reference their repo. 20 individual <100-word emails, one link (docs), one ask (try free tier, reply with what's missing). Subject: "Compliance check API for AI payment agents — wanted your take."
- **One technical post:** "How we built a pre-flight OFAC + RBI check for autonomous AI agents in Python." dev.to + Show HN + LinkedIn. Not marketing — proof of depth. HN comments = second outreach wave.
- **Design partners (before launch):** 3 engineers (hackathon / GitHub / your ECE network). "Free early access, 30-min call, tell me what's wrong."
- **The EU AI Act open:** "Your autonomous payment agents are high-risk AI under the EU AI Act. You need auditable trails by Aug 2, 2026. We produce that per call. How are you solving it today?" They're either not solving it (prospect), building it (urgent prospect), or done (ask what they built).
- **The licensed-partner track (Path B):** in parallel, one conversation with a licensed MTO / authorised-dealer / BaaS partner who could run RemittanceRail under their license and share the take-rate. That's the venture unlock.

**Milestones:** Wk4 — live API + docs + 3 design partners calling for real. Wk8 — first paid Starter + one published article. Wk12 — 5 paying, 2 on Growth, MRR >$500. Wk16 — 10 paying + one compliance officer used an audit receipt in a real review = your case study.

---

## 11. What I Changed & Why (cleanup log)

- **Reframed one product → a two-rail product line.** The presentation smuggled in a whole second product (RemittanceLayer). Named it, gave it a job, and connected the money: Rail 2 feeds Rail 1.
- **Made the money explicit and two-engine.** Added the take-rate math — that's the venture story the per-call table alone couldn't tell.
- **Added the regulatory fork (§3).** The source silently assumed you can move money. You can't, not solo, not legally, not fast. Called it out and gave a de-risked path that keeps the upside. This is the honest thing that changes YC-vs-internship.
- **Resolved contradictions:** BackgroundTasks (not Celery) at MVP; `wallet_address` everywhere (not `wallet`); `upstream_health_log` kept, `sanctions_cache` dropped (Redis TTL, not a table); reconciled the two phase orderings into one sequence with testing in parallel.
- **Merged the two data models and the two check-lists** into single canonical versions; folded the RBI/FEMA/GIG-TIER checks from the presentation into the base pipeline (5 checks) — the India angle is an asset, especially for the Razorpay path.
- **Cut the duplication:** the source repeated the architecture, pipeline, security, and API sections nearly verbatim across two drafts. One canonical version each.
- **Kept intact (already good):** fail-closed doctrine, RFC 7807 errors, key security, 3-layer rate limiting, the verdict truth table, 100%-branch-coverage testing rule, the "no billing until 5 customers" rule.

---

## 12. Open Questions For You

Real forks I can't decide for you:

1. **Path A vs B for the *business* (not the demo).** Sell the primitive to licensed movers, or pursue operating remittance via a licensed partner? (Demo is testnet either way.) This shapes the pitch.
2. **Corridor focus.** India-first (RBI/FEMA depth, Razorpay-aligned) or US/EU-first (OFAC/EU-AI-Act, cleaner legally)? Affects which checks you polish for the demo.
3. **YC narrative framing.** Lead with "compliance primitive for agentic payments" (infra) or "sub-1% compliant remittance rail" (consumer volume)? Same codebase, very different pitch.

Tell me which, and I'll turn the relevant section into the actual pitch + build the Phase-0/1 scaffold.

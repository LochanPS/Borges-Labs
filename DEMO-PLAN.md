# Hackathon Demo Plan — RemittanceRail on ComplianceAPI

*Shared source of truth for the split between the **main product repo** (this one)
and the **hackathon demo repo** (to be created). Written for Smart Horizon 2026,
Problem Statement SH-FIN-04, team Potato Rangers (SHIH26-TID-531).*

> **One-line thesis:** an autonomous AI agent tries to move money; our compliance
> gate decides — in one pre-flight API call — whether each payment is allowed,
> and only an `APPROVE` can settle on-chain. No pass, no payment.

---

## 0. The two repos and the boundary between them

| | **Main repo (`Borges-Labs`)** | **Demo repo (new)** |
|---|---|---|
| Role | The **company product** — a general trust/authorization engine for autonomous financial agents | A **hackathon proof** — one vertical slice (India remittance) that runs *on top of* the product |
| Depth | Broad, real, long-lived | Shallow, sellable, disposable-if-needed |
| Language | Go | Go (dogfoods the engine) + a thin web UI |
| Owns | `authorize-svc` engine, policy versioning, two-plane arch, Ed25519-signed decisions, audit hash-chain, rate limiting, auth, SDKs, dashboard scaffolding | Sample AI agent, remittance policy pack, `RemittanceGateway.sol`, UPI-skin UI, org + platform dashboards |

**Decision (locked): the demo dogfoods the real engine.** The demo does NOT
re-implement authorization. It calls the main engine's `POST /v1/authorize` and
only *adds* the vertical-specific layers around it. On stage this lets us say
"the demo runs on our actual production engine — the same one we sell."

**Escape hatch:** if wiring the live dependency eats too much of the 48 hours,
the four checks are simple enough to stub inline and swap the real engine back in
later. Repo-coupling must never be the thing that sinks the demo.

### What is NOT our product (important framing)

The **AI agent is not the product.** It belongs to the *customer* (the org). We
build a sample agent purely so something realistic calls our gate. We sell the
**gate**, not the agent. This is why there are two dashboards (see §4).

---

## 1. The live demo — what the audience sees

1. A **free/local LLM agent** (a fintech's "payout agent") is told: *"pay this
   week's contractors."* It holds a contact list — the 4 teammates' UPI handles.
2. Before **every** payout the agent calls `POST /v1/authorize`. The gate is
   **mandatory and on-screen**: the call, the request, and the verdict are shown
   before any money moves.
3. Contacts resolve to verdicts by policy: most **APPROVE**, one teammate
   **DENY** (blocked payee). The agent proceeds on its own — pays the APPROVEs,
   skips the DENY — narrating each decision.
4. **Live policy edit (the interactive beat):** add a judge's handle, flip
   policy — block one judge, allow another — re-run, and the gate visibly
   changes behavior in real time. No redeploy.
5. Each **APPROVE** → engine returns an Ed25519-signed decision → demo wraps it
   in an **ECDSA** signature → `RemittanceGateway.sol` on **Base Sepolia**
   settles **test-USDC** → UI shows a UPI-style **UTR** that is really a
   **Basescan-verifiable tx hash**. A **DENY** yields no signature, so the
   contract *cannot* execute. Enforcement is cryptographic, not cosmetic.

**Two failure/skip paths to rehearse:** a sanctions/blocklist DENY (fast, ~8ms
short-circuit) and a spend-cap DENY (agent tried to exceed its budget).

---

## 2. Settlement rail — UPI skin, on-chain underneath

- **What judges see:** VPAs (`name@bank`), amounts in ₹, a "UTR" reference — a
  familiar Indian-remittance surface.
- **What actually happens:** on `APPROVE`, the demo signs (ECDSA) and calls the
  Solidity gateway; test-USDC moves on Base Sepolia; the "UTR" shown is the real
  transaction hash, clickable through to Basescan.
- **Why:** familiar to the room *and* independently verifiable — the strongest
  combination for a judge who asks "is this real?"

### Signature reality (do not skip this)

The engine signs decisions with **Ed25519** (great for third-party audit
verification, wrong curve for the EVM). Solidity's `ecrecover` needs
**secp256k1 / ECDSA**. So the demo keeps a **separate ECDSA signing step** that
runs only on an `APPROVE` verdict and produces the on-chain-verifiable signature.
The engine is untouched; the crypto-gating lives entirely in the demo repo.

---

## 3. The compliance policy pack (demo-specific)

Four checks, shallow but real, expressed against the engine's request vector
(`agent_id`, `action`, `amount`, `currency`, `target`, `jurisdiction`, `context`,
`idempotency_key`):

| Check | What it does | Verdict on hit | Target latency |
|---|---|---|---|
| **Sanctions / blocklist** | fuzzy-match payee against a small static OFAC-style + demo blocklist | DENY | ~5–8ms |
| **Spend policy** | per-agent budget via Redis TTL counter (e.g. weekly cap) | DENY / REVIEW | ~8ms |
| **Jurisdiction** | embargo / allowed-corridor flag | DENY | ~2ms |
| **RBI rule** | LRS ₹7 lakh cap + a Form-A2 purpose code | DENY / REVIEW | ~12ms |

The "block a judge" beat is just adding a payee to the blocklist predicate's data
(or an org contact flagged `blocked`) and re-publishing the policy — which the
engine already supports via policy versioning.

---

## 4. The two dashboards

- **Org dashboard (the customer's view):** their agent's activity, their contact
  list with per-contact allow/block flags, their spend against cap, their audit
  receipts. This is where the "block a judge" edit happens.
- **Platform dashboard (your god-view):** every org's calls in one place —
  volume, verdict mix, latency, and the number that matters for the pitch:
  **billable calls / value moved → take-rate**. This is the "take money" screen.

Both read from the engine's audit/decision records; neither re-computes anything.

---

## 5. Tech choices (locked)

- **Engine / gate:** Go, reused from this repo (`authorize-svc`).
- **Agent brain:** free/local LLM (e.g. an Ollama model or a free API tier) doing
  a small tool-calling loop: `list_contacts` → `check_compliance` (our API) →
  `send_payment` on APPROVE. Keep the toolset tiny for live reliability; have a
  scripted fallback path rehearsed in case the model flakes on stage.
- **Chain:** Solidity `RemittanceGateway.sol` on Base Sepolia, test-USDC, ECDSA
  gating via `ecrecover`. Go side uses `go-ethereum` + `abigen` bindings.
- **UI:** thin web app (org + platform dashboards + the agent console).

---

## 6. Build order for the 48 hours (demo repo)

1. Stand up the engine as a dependency/sidecar; get one real `APPROVE` and one
   `DENY` back through `POST /v1/authorize`. **← "it's real" proof.**
2. Remittance policy pack (4 checks) + seed data (4 contacts, 1 blocked).
3. Agent loop calling the gate; console that shows call → verdict → action.
4. ECDSA signer + `RemittanceGateway.sol` on Base Sepolia; APPROVE settles,
   DENY cannot. **← the crypto-enforcement proof.**
5. UPI-skin on the UI (VPAs, ₹, UTR = tx hash).
6. Org dashboard + live block/allow edit. **← the interactive beat.**
7. Platform dashboard (volume + take-rate). **← the business proof.**
8. Rehearse both DENY paths and the scripted-agent fallback.

Everything past step 8 is roadmap slides, not code.

---

## 7. Open decisions (need your call before/while building)

- **Local LLM specifics:** which free model/runtime (Ollama locally? a free
  hosted tier?) — decides how the agent tool-loop is wired and how robust it is
  live without network.
- **Real UPI vs UPI-skin:** confirmed **skin only** (no real bank rails) for the
  demo — real UPI needs a licensed PSP and is out of hackathon scope.
- **Contacts:** using the 4 teammates' handles is fine for a controlled demo;
  for judges, use display handles you control, not their real payment IDs.

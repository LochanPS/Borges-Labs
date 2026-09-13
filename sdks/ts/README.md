# @trust-infra/sdk (TypeScript / Node)

Thin Node client for the **AI Transaction Authorization Infrastructure** `/v1` API.
It canonicalizes and HMAC-signs every request, verifies the **Ed25519** signature on
each decision against the published public key, and applies an explicit fail-mode.
It **never** turns an upstream failure into a silent `APPROVE` (TRD §10).

Zero runtime dependencies — uses `node:crypto` and the global `fetch` (Node ≥ 18).
Types are generated from the frozen contract in [`/contracts`](../../contracts) (see
[Generated types](#generated-types)), the same source the Go types and Python SDK bind.

## Install

```bash
npm install @trust-infra/sdk
```

## Three-line integration

```ts
import { Client } from "@trust-infra/sdk";

const client = new Client({ apiKey: "azn_live_...", publicKeys: jwks }); // jwks from GET /v1/keys/public
(await client.authorize(txn)).enforce();   // verifies the Ed25519 receipt; throws unless APPROVE
await charge(txn);                          // your existing payment call, reached only on APPROVE
```

`txn` is an `AuthorizeRequest`
([schema](../../contracts/schemas/authorize-request.schema.json)):

```ts
const txn = {
  agent_id: "procurement-agent-v2",
  action: "payment.create",
  amount: "1200.00",           // decimal STRING — never a float
  currency: "USD",
  target: { type: "vendor", id: "acme-supplies" },
  idempotency_key: "idem_01HXYZ...",
};
```

Runnable offline version: [`examples/quickstart.ts`](examples/quickstart.ts) (`npm run example`).
An end-to-end test over a real socket is in [`test/e2e.test.ts`](test/e2e.test.ts).

## Shadow mode (the adoption wedge, PRD §9)

```ts
const decision = await client.shadow(txn);  // evaluated + logged, NEVER enforced
log.info(`would have been ${decision.verdict}`);
await charge(txn);                           // payment path untouched
```

A decision from a shadow-mode key carries `shadow === true`; `.enforce()` honors that
and never blocks on it. `decision.approved` is `true` only for an enforceable APPROVE.

## API

| Method | Endpoint | Returns |
|---|---|---|
| `authorize(txn)` | `POST /v1/authorize` | `Promise<DecisionResult>` (signature verified) |
| `shadow(txn)` | `POST /v1/authorize` | `Promise<DecisionResult>` (advisory) |
| `capture(id)` | `POST /v1/authorize/{id}/capture` | `Promise<HoldState>` |
| `void(id)` | `POST /v1/authorize/{id}/void` | `Promise<HoldState>` |
| `verifyDecision(dec)` | — (local) | `DecisionResult` with `signatureVerified: true` |
| `fetchPublicKeys()` | `GET /v1/keys/public` | `Promise<Jwks>` |

### Verify any decision (no secret needed)

`verifyDecision` reproduces the `ti-decision-canon/1` canonical bytes and checks the
Ed25519 signature against the published key, so a customer, auditor, or regulator can
validate a receipt they were handed:

```ts
import { verifyDecision, SignatureVerificationError } from "@trust-infra/sdk";
try {
  verifyDecision(decision, jwks);  // or client.verifyDecision(decision)
} catch (e) {
  if (e instanceof SignatureVerificationError) { /* tampered or not ours */ }
}
```

## Fail modes — `onUnavailable`

When the plane is unreachable or returns `503`, the SDK applies your policy. Fail-mode
results are **synthetic**, **unsigned**, and flagged `degraded === true`.

| Mode | Behavior when unavailable |
|---|---|
| `OnUnavailable.FailClosed` *(default)* | Synthetic `DENY`. `.enforce()` throws → payment blocked. |
| `OnUnavailable.FailOpen` | Synthetic `APPROVE` — **explicit, logged, degraded**. Opt-in only. |
| `OnUnavailable.LocalCache` | Replay the last signed decision cached for this `idempotency_key`; on a miss, fail **closed**. |

The only way to get an `APPROVE` out of an outage is to explicitly choose `FailOpen`;
no code path silently approves on error.

## Errors (RFC 7807)

Non-2xx responses are parsed from `application/problem+json` into typed errors:
`ValidationError` (400/422) · `AuthenticationError` (401) · `ReplayError`
(`replay_detected`) · `ForbiddenError` (403) · `NotFoundError` (404) · `ConflictError`
(409) · `RateLimitedError` (429, with `.retryAfter`) · `ServiceUnavailableError` (503).
Each carries `.status`, `.title`, `.detail`, `.code`, and field-level `.errors`. Base:
`ProblemError` → `TrustInfraError`. A decision whose signature fails verification
throws `SignatureVerificationError` and is never returned as trustworthy.

## Generated types

Wire types are emitted from the JSON Schemas by a zero-dependency generator,
[`contracts/tools/gen-ts.mjs`](../../contracts/tools/gen-ts.mjs), which writes both
`contracts/gen/ts/contractsv1/types.ts` (canonical, mirroring `contracts/gen/go`) and
the vendored copy this package ships, `src/contracts/generated.ts`.

```bash
npm run gen:types   # regenerate after a contract change
```

`test/contractExamples.test.ts` parses the committed contract examples against the
generated types, so schema drift surfaces as a test failure.

## Two signatures, kept distinct (ROADMAP A#1)

| | Direction | Algorithm | Where |
|---|---|---|---|
| **Request auth** | caller → us | HMAC-SHA256 (symmetric) | `X-Signature` header, `azn-hmac/1` |
| **Decision receipt** | us → everyone | Ed25519 (asymmetric) | `Decision.signature`, `ti-decision-canon/1` |

## Development

```bash
npm install
npm run gen:types     # regenerate contract types
npm run build         # tsc -> dist/
npm test              # node --test via tsx
npm run example       # runnable offline quickstart
```

Run the suite against a real service by setting `TRUST_INFRA_BASE_URL` and
`TRUST_INFRA_API_KEY` (the live test is skipped otherwise).

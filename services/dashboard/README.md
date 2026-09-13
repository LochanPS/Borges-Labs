# dashboard — Control Plane UI (Next.js)

Next.js (App Router) control-plane UI over the authorize-svc control-plane + audit read
APIs (Task 5.1). Four areas:

1. **Overview** — decision volume, verdict mix, p50/p95 latency, active policy version.
2. **Policies** — author/edit rules for the local predicate types + budgets, publish an
   immutable signed version, view version history, and roll back.
3. **Audit log** — filterable table (verdict, agent); each row opens the receipt.
4. **Decision receipt** — inputs, matched rules, policy version hash, and an in-browser
   **Verify signature** button that validates the Ed25519 receipt client-side against the
   published public key. A "Simulate tamper" control shows detection.

Plus **API keys**: create-once secret reveal + revoke.

Types are the generated contract types (`src/lib/contracts/generated.ts`, produced by
`contracts/tools/gen-ts.mjs`) — the same source the TS SDK and `contracts/gen/ts` use.

## Run

```bash
cp .env.example .env.local     # optional: set AUTHZ_BASE_URL / AUTHZ_API_KEY / Clerk keys
npm install
npm run gen:types              # refresh generated contract types
npm run dev                    # http://localhost:3000
```

- **No backend?** Leave `AUTHZ_*` unset — every screen renders from seeded mock data, and
  the receipt's Verify button still validates a **real** Ed25519 signature (the mock
  decisions are signed by a per-process key whose JWKS the app serves).
- **Live backend?** Set `AUTHZ_BASE_URL` + `AUTHZ_API_KEY` (an admin key). The server-side
  client HMAC-signs (`azn-hmac/1`) each control-plane request; the key never reaches the
  browser. On any call error it falls back to mock so the UI stays usable.

## Auth (Clerk, optional)

With `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` + `CLERK_SECRET_KEY` set, sign-in is enforced via
middleware. Without them the app runs in **dev-bypass** mode (a banner shows). Get keys at
https://clerk.com.

## Test / build

```bash
npm test     # client-side Ed25519 verify: valid, tamper, unknown/revoked key, bad alg
npm run build
```

## Contract gaps (flagged for follow-up)

The frozen `/v1` contract does not yet expose everything this UI wants. Where an endpoint
is missing, the screen uses mock/derived data and targets the intended additive path:

- **No list-policies endpoint** — the policies list derives from `GET /v1/policies/active`
  → `GET /v1/policies/{id}` when live. Add `GET /v1/policies`.
- **No key-management endpoints** — only `GET /v1/keys/public` exists. The keys screen is
  mock-backed and targets `POST /v1/keys` / `POST /v1/keys/{id}/revoke`. Add these
  (additive) to the contract + authorize-svc, then wire `lib/api.ts`.
- Control-plane view types (Policy, PolicyVersion, BundleRef, ApiKey) are hand-mirrored in
  `src/lib/contracts/controlplane.ts` from the OpenAPI components; a generator pass could
  emit them.

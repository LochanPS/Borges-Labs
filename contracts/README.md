# /contracts — Source of Truth (FROZEN, v1)

The single source of truth for every component. Every other service, SDK, and the
dashboard depend on these shapes. **Frozen** per ROADMAP Task 0.2: change `/v1` only
additively; breaking changes go to `/v2` with `/v1` maintained.

## Layout

```
contracts/
  openapi.v1.yaml                 HTTP surface (OpenAPI 3.1): decision plane +
                                   control plane (/v1/policies …, incl. simulate)
  schemas/
    common.schema.json            shared defs: Money, Target, Counter(Snapshot),
                                   MatchedRule, Obligation, Signature, ULID, ...
    authorize-request.schema.json POST /v1/authorize body
    decision.schema.json          Decision (response + stored audit record)
    policy.schema.json            Policy document (control plane; $defs/Rule is the
                                   shared rule shape openapi.v1.yaml references)
    error.schema.json             RFC 7807 problem+json
  examples/
    authorize-request.example.json
    decision-approve.example.json
    decision-deny.example.json
    policy.example.json
  gen/go/                         generated Go structs (module
                                  github.com/trust-infra/contracts/gen/go)
  gen/ts/                         generated TypeScript types (contractsv1/types.ts),
                                  emitted by tools/gen-ts.mjs; the TS SDK vendors a copy
  tools/validate.py               contract test: schemas + examples + OpenAPI
  tools/gen-ts.mjs                zero-dep TS type generator (schemas -> gen/ts + SDK)
```

Canonicalization of the Ed25519 decision signature: see
[`/docs/decision-canonicalization.md`](../docs/decision-canonicalization.md)
(`ti-decision-canon/1`).

## The two signatures — do not conflate (ROADMAP A#1)

- **Request authentication (caller → us): HMAC, symmetric.** Carried in HTTP headers
  (`X-Api-Key`, `X-Signature`, `X-Nonce`, `X-Timestamp`) — see the OpenAPI security
  schemes. Authenticates the caller.
- **Decision signature (us → everyone): Ed25519, asymmetric.** The `Decision.signature`
  object. Verifiable by any third party against the published public key
  (`GET /v1/keys/public`) with no secret. This is the tamper-evident audit receipt.

## Determinism (ROADMAP A#7)

A decision is a pure function of `(request, policy_version, evaluated_at,
counter_snapshot)`. `evaluated_at` and `counter_snapshot` are **orchestrator-injected**
inputs, explicit in `AuthorizeRequest`. Predicates MUST NOT read the wall clock, RNG,
or the network; that is what makes every decision byte-for-byte replayable. Money is a
decimal **string** (never a float) so the signature canonicalizes stably.

## Design notes worth knowing

- `amount` and all monetary values are strings (`MonetaryAmount`), not numbers.
- `verdict` APPROVE/DENY/REVIEW; predicate `result` adds `UNAVAILABLE` for an enriched
  predicate that could not complete — its fail-mode then governs the verdict, never a
  fabricated SATISFIED (TRD §5, §21).
- `Decision.signature.key_id` is mandatory for key rotation.
- `Decision` doubles as the stored record: `record_hash` + `signature_verified` are
  record-only fields the audit read path adds; they are **not** signed.
- `shadow: true` marks an advisory/log-only decision the caller must not enforce
  (advisory-first, ROADMAP A#5); it IS part of the signed bytes.

## Regenerate / verify

Validate the whole contract (schemas, examples, OpenAPI):

```bash
python contracts/tools/validate.py
```

Build + test the generated Go types:

```bash
cd contracts/gen/go && go test ./...
```

Regenerate the TypeScript types after a schema change (zero-dependency, Node only):

```bash
node contracts/tools/gen-ts.mjs
```

The Go structs in `gen/go` are the reference binding; `gen/ts` mirrors them for the TS
SDK (Task 4.2) and the dashboard. The Python SDK (Task 4.1) binds the same schemas.

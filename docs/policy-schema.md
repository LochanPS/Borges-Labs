# Policy schema, versioning & signing (`ti-policy-canon/1`)

Control-plane policies (ROADMAP Task 2.1, TRD §6). Authoritative schema:
[`contracts/schemas/policy.schema.json`](../contracts/schemas/policy.schema.json).
Implementation: [`services/authorize-svc/internal/policyctl`](../services/authorize-svc/internal/policyctl)
(MVP fold per ROADMAP A2#2 — no separate Node `policy-svc` until the dashboard lands).

## What a policy is

A policy belongs to **one org**, targets **one or more agents** (empty = all agents in
the org), and lists **typed rules**. There is **no compiler** (ROADMAP A#6): publishing
a policy means *validate → content-hash → Ed25519-sign → store*. Nothing is transformed
into another representation.

```jsonc
{
  "org_id": "org_acme",
  "name": "vendor payments",
  "agents": ["procurement-agent-v2"],      // [] or omitted = every agent
  "rules": [ /* typed rules, see below */ ]
}
```

## Rule types

Six **local** types are evaluated by the decision engine today (Task 1.4); three
**placeholder** types (budget + enrichment) are valid to author, version, and sign now
but are **not yet enforced** by the local engine — Phase 3 / enrichment adds them.

| `type` | Class | Required params |
|---|---|---|
| `per_transaction_limit` | local | `max` (decimal string); `currency` optional |
| `vendor_allowlist` | local | `vendors` (non-empty) |
| `vendor_blocklist` | local | `vendors` (may be empty) |
| `agent_permission` | local | at least one of `allowed_actions` / `allowed_targets` |
| `time_window` | local | `start_minute`, `end_minute` in `[0,1440)`; `weekdays` optional (0=Sun..6=Sat) |
| `jurisdiction_currency` | local | `allowed` (map jurisdiction → currency codes) |
| `rolling_budget` | **placeholder** (Phase 3) | `window` (`day`\|`month`\|`rolling`), `limit` |
| `sanctions_screen` | **placeholder** (enrichment) | `provider`, `fail_mode` optional |
| `vendor_risk` | **placeholder** (enrichment) | `provider`, `threshold` (0..100), `fail_mode` optional |

Every rule has an `id` (unique within the policy) and an optional per-rule `agents`
narrowing. Each type fixes exactly its allowed fields (`additionalProperties:false`), so
a stray or mistyped field is rejected with a JSON-pointer at the offending path.

Validation runs the schema **plus** an engine-parity check: the local subset of a
policy is fed through the decision plane's loader (`internal/policy`), guaranteeing a
policy that publishes here is one the decision node can actually serve.

## Versioning (immutable, content-addressed)

On publish the working copy is canonicalized and hashed into a **version hash**:

```
version_hash = "polv_" + SHA-256( JCS( signed_view ) )
```

where `signed_view` is the ordered set `{policy_id, org_id, name, agents, rules}` and
`JCS` is RFC 8785 JSON Canonicalization. Consequences:

- **Identical content → identical hash.** Republishing an unchanged policy is a no-op
  (`ON CONFLICT DO NOTHING`); the existing signed version is reused.
- **Any edit → a new hash → a new immutable row.** Old versions are never rewritten
  (`policy_versions` is append-only at the DB layer via trigger).
- **Identity is bound in.** Because org/policy/name/agents are inside the hash, a
  version hash is unique to *this* policy's content and a signature cannot be lifted
  onto another policy.

`parent_hash` records which version was active when a version was published, giving the
history a lineage independent of wall-clock order.

> Note: this `polv_` version hash is distinct from the decision plane's local
> content hash (`pol_`, `internal/policy`), which hashes only the predicate set. Task
> 2.2 wires how a published bundle propagates to decision nodes and which hash each
> decision cites.

## Signing (`ti-policy-canon/1`)

The **same Ed25519 key** that signs decision receipts (see
[decision-canonicalization.md](decision-canonicalization.md)) signs policy versions,
using the detached signer over the canonical `signed_view` bytes. The signature carries
`{algorithm, key_id, value, canonicalization: "ti-policy-canon/1"}`.

Any third party (auditor, regulator) verifies a version with only the version content
and the public key published at `GET /v1/keys/public` — no shared secret. See
`policyctl.VerifyVersion`. Tampering with any signed field fails verification.

## Draft, publish, list, rollback

- **Draft vs published.** A new policy is `draft`; the first successful publish flips it
  to `published` and sets `active_version_hash`. Editing the working copy afterward does
  **not** unpublish it — the active version keeps serving until the next publish.
- **List versions.** Newest-first, each with its signature, author, and `parent_hash`.
- **Rollback = republish a prior hash** (TRD §6). Rollback re-points
  `active_version_hash` at an existing version and resets the working copy to that
  version's content. Because versions are content-addressed and immutable, **no new row
  is created** — the prior signed version is reinstated exactly.

## HTTP API (Task 2.2)

Control-plane endpoints, org-scoped by the authenticated API key (RFC 7807 errors; a
`ValidationError` is `422` with field-level `errors[]`). They live in the same binary as
the decision plane for MVP (A2#2) and split into policy-svc at Phase 5.

| Method + path | Action |
|---|---|
| `POST /v1/policies` | create a draft |
| `GET /v1/policies/{id}` | read the working copy |
| `PUT /v1/policies/{id}` | edit the working copy |
| `POST /v1/policies/{id}/publish` | validate → version → sign → store; set active |
| `POST /v1/policies/{id}/rollback` | `{version_hash}` → re-point active at a prior version |
| `GET /v1/policies/{id}/versions` | list versions, newest-first |
| `POST /v1/policies/{id}/simulate` | dry-run a version (or the draft) against a batch of requests (Task 2.3) |
| `GET /v1/policies/active` | the org's currently serving version (A#4) |

> Not yet in `contracts/openapi.v1.yaml` — a follow-up adds these paths + the policy
> schema to the OpenAPI document so SDK types generate from them.

## Bundle propagation (Task 2.2, A#4)

The decision plane never calls the control plane synchronously (TRD §3). Instead
[`internal/bundle.Provider`](../services/authorize-svc/internal/bundle/bundle.go) holds
each org's compiled active bundle in a process-local cache:

- **Hot path** reads the cache only. A cold miss does one bounded load, then it's pure
  cache.
- **Convergence.** A same-process publish/rollback calls `Invalidate` → immediate. A
  publish on another instance converges within `AUTHZ_BUNDLE_REFRESH_TTL` (default 5s)
  via the background refresher.
- **Last-known-good.** If the control-plane store is unreachable on refresh, the cached
  bundle keeps serving (§21) — decisions continue, edits pause. No servable bundle and
  no cache → controlled 503, never a guessed verdict.
- **Fallback.** With a static boot policy configured (`AUTHZ_POLICY_FILE`), an org that
  has never published falls back to it instead of 503 (file/GitOps mode, Task 1.7).

Each decision cites the exact `polv_` version hash it was evaluated under.

## Shadow mode & simulate (Task 2.3, advisory-first — A#5)

**Shadow mode** is the adoption wedge and the liability-safe default: you inform, the
customer's code decides. It is a **per-key** flag (`api_keys.shadow`, migration 0005),
defaulting to `true` on a freshly minted key. A shadow key's decisions are fully
evaluated, signed, and written to the audit log — but returned `shadow: true` (a
**signed** field, so the marker cannot be stripped) plus an `X-Shadow: true` response
header, so the SDK/caller does **not** enforce them. Flipping one agent's key to
`shadow=false` (`authz-keygen -enforce`) is the go/no-go lever for enforcement
(ROADMAP §6.1). Shadow decisions are audited exactly like enforced ones, so "what did
this agent's traffic do last week" is answerable from the log.

**Simulate** (`POST /v1/policies/{id}/simulate`) dry-runs a policy against a batch of
supplied requests and returns the would-be verdicts — the "what would this policy have
done" demo. Body: `{ "version_hash"?: "polv_…", "requests": [AuthorizeRequest, …] }`.
With a `version_hash` it evaluates that immutable published version; without one it
validates and evaluates the current working-copy **draft** (preview edits before
publishing). Each request's own `evaluated_at` is honored (replaying history). Results
are **unsigned** and every one is `shadow: true` — a simulation is never enforceable and
nothing is persisted.

## Storage

[`deploy/migrations/0003_policies.sql`](../deploy/migrations/0003_policies.sql):
`policies` (mutable working copy + active pointer) and `policy_versions` (immutable,
append-only, signed). The application role should be granted only `INSERT`/`SELECT` on
`policy_versions` (commented `REVOKE`/`GRANT` in the migration).
[`0004_org_active_bundles.sql`](../deploy/migrations/0004_org_active_bundles.sql): the
mutable per-org active-bundle pointer the decision plane converges to.

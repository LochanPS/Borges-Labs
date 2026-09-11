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

## Storage

[`deploy/migrations/0003_policies.sql`](../deploy/migrations/0003_policies.sql):
`policies` (mutable working copy + active pointer) and `policy_versions` (immutable,
append-only, signed). The application role should be granted only `INSERT`/`SELECT` on
`policy_versions` (commented `REVOKE`/`GRANT` in the migration).

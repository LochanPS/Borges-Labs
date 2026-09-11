# Policy files

The decision engine evaluates a **policy**: an ordered set of typed predicates. For
MVP there is no separate policy service (ROADMAP A2#2) — `authorize-svc` loads a
policy from a JSON file, so it can live in your repo and be PR-reviewed (GitOps).
Phase 2 replaces the file with a published, content-hashed bundle; the evaluated
policy is identical, only the source changes.

Point the service at a file with `AUTHZ_POLICY_FILE=/path/to/policy.json`. With no
file set, the binary uses its embedded default (`internal/policy/default.policy.json`).
Loader + validation: `services/authorize-svc/internal/policy`.

## Format

```json
{
  "version": "pol_my_policy_v1",
  "predicates": [
    { "id": "limit", "type": "per_transaction_limit", "max": "10000.00", "currency": "USD" }
  ]
}
```

- `version` — optional. If omitted, a deterministic content hash (`pol_` + SHA-256 over
  the RFC 8785 JCS form of the predicates) is computed, so an unchanged policy always
  cites the same `policy_version_hash` on every decision. Set it explicitly to pin a
  human-readable version.
- `predicates` — the rules. Each needs a unique `id` and a `type`. Unknown JSON keys are
  rejected (a typo fails to load rather than being silently ignored). An optional
  `agents` array scopes a rule to specific `agent_id`s; omit it to apply to every agent.

An **empty** applicable set denies by default (TRD §6/§20): a request from an agent no
predicate applies to is denied, never approved.

## The six local predicate types (Task 1.4)

| `type` | Fields | Denies when |
|---|---|---|
| `per_transaction_limit` | `max` (required, decimal string), `currency` (optional) | amount > max; currency mismatch ⇒ REVIEW |
| `vendor_allowlist` | `vendors` (required, non-empty) | vendor target not on the list |
| `vendor_blocklist` | `vendors` | vendor target on the list |
| `agent_permission` | `allowed_actions`, `allowed_targets` (≥1 required) | action/target not permitted |
| `time_window` | `start_minute`, `end_minute` (0–1439, required), `weekdays` (0=Sun..6=Sat) | outside `[start,end)` (wraps midnight if end ≤ start) or weekday |
| `jurisdiction_currency` | `allowed` (required, `{ "US": ["USD"] }`) | currency not permitted in the request's jurisdiction |

Enriched/stateful types (`rolling_budget`, `sanctions_screen`, `vendor_risk`) are
**not** loadable here — they belong to Phase 3 / enrichment and are rejected with a
clear error.

## Combination

Predicate results combine by strict precedence (TRD §5): any **DENY** ⇒ DENY; else any
**REVIEW** ⇒ REVIEW; else all satisfied ⇒ APPROVE. Order-independent and deterministic
for a given request + policy + `evaluated_at`.

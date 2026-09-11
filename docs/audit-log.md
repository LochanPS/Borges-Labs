# Audit log — append-only, tamper-evident decision record

*Implements TRD §12–14 and ROADMAP Task 1.6 / A#10. Code: `services/authorize-svc/internal/audit`, migration `deploy/migrations/0002_decisions.sql`, endpoints in `internal/server/decisions.go`.*

Every decision returned by `POST /v1/authorize` is persisted to the append-only
`decisions` table. The write is **asynchronous** — it happens after the response is
sent, so it never adds to the decision's `latency_ms`.

## What it guarantees

1. **Append-only.** No `UPDATE`, no `DELETE`. A Postgres `BEFORE UPDATE OR DELETE`
   trigger rejects mutations at the storage layer; the application role should also be
   granted only `INSERT`/`SELECT` (see the migration's trailing note). Retention does
   **not** delete rows (see below).

2. **Tamper-evident hash chain (per org).** Each record stores
   `record_hash = SHA-256( JCS( prev_hash ‖ record fields ) )`, where `prev_hash` is the
   previous record's hash for that org (the first record chains to the sentinel
   `rh_genesis/1`). Mutate any stored field and the recomputed hash no longer matches;
   rewrite a `record_hash` and the *next* record's `prev_hash` no longer links. The
   canonical form is RFC 8785 JCS — the same scheme the decision signature uses — so a
   third party reproduces the bytes exactly.

3. **Ed25519 signature.** The decision's asymmetric signature (Task 1.5) is stored
   verbatim and re-verified at read time against the published public key
   (`GET /v1/keys/public`).

`GET /v1/decisions/{id}` recomputes **both** at read time and returns
`signature_verified: true` only when the Ed25519 signature validates **and** the
`record_hash` chain link is intact. Either failing (any mutated row) yields `false`.

## Field-level encryption (A#10)

The sensitive request fields — `amount`, `target.type`, `target.id` (the counterparty)
— are encrypted at rest with **AES-256-GCM** when `AUTHZ_AUDIT_ENCRYPTION_KEY` is set
(a 32-byte key in base64 or hex). Without a key they are stored as plaintext (dev/CI).

- The `record_hash` is always computed over **plaintext**, so a party that can decrypt
  can recompute it independently — encryption never breaks the chain.
- Non-sensitive filter fields (`agent_id`, `verdict`, `evaluated_at`) stay plaintext so
  the list endpoint can index and filter them.
- Ciphertext is self-marking (`enc:v1:` prefix); a row written before a key existed
  reads back as plaintext, so enabling a key is not a breaking change for old rows.

## Retention (A#10)

Retention is **per tier** (`AUTHZ_AUDIT_RETENTION_DEFAULT` plus a built-in per-tier
table in `config`). Each record carries `retain_until = created_at + retention(tier)`.
Because the table is append-only, retention is enforced by **crypto-shredding** — once
`retain_until` passes, the tier's data-encryption key is destroyed, rendering that
window's sensitive ciphertext permanently unreadable — **not** by deleting rows. The
chain and the signed receipt remain intact and verifiable; only the sensitive fields
become unrecoverable. The background shred job itself is a documented post-MVP TODO
(the amendment in ROADMAP Task 1.6 defers it); the schema, config, and `retain_until`
stamping are in place.

## Async write & durability

The write path is an in-process buffered channel drained by a single background worker
(`audit.Writer`):

- The handler calls `Enqueue` **after** `writeJSON`, so persistence is off the hot path.
- Enqueue **does not drop**: a full buffer applies backpressure to the (already-sent)
  request goroutine; on shutdown, queued records are flushed before the DB pool closes.
- A single worker keeps each org's chain in a consistent order within a process. Across
  instances, the Postgres store takes a **per-org advisory lock** (`pg_advisory_xact_lock`)
  so concurrent appends stay linear.

**MVP limitation → upgrade.** Records still buffered in memory are lost on a hard crash.
The documented upgrade (TRD §14, §23) is a durable queue — NATS, then Kafka as the audit
backbone — behind the same `audit.Store` interface, with no change to the write API.

## Endpoints

- `GET /v1/decisions/{id}` — one record for the caller's org, with `record_hash` and
  read-time `signature_verified`. Cross-org ids are "not found" (no cross-tenant read).
- `GET /v1/decisions` — newest-first page. Filters: `agent_id`, `verdict`, `from`/`to`
  (RFC 3339 bounds on `evaluated_at`, `from` inclusive / `to` exclusive). Pagination is
  an opaque `cursor` (bounded `limit`, 1..200, default 50).

Both are authenticated and org-scoped (same `X-Api-Key`/`X-Signature`/`X-Nonce`/
`X-Timestamp` scheme as `POST /v1/authorize`).

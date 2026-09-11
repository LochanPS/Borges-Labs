# Running the service

The tests need **nothing** — `go test ./...` runs fully in memory. You only need
Postgres + Redis to run the **live** service (manual curl, a demo, real end-to-end).

There are two ways to get those stores. **Cloud (managed) is the recommended path** —
no install, free tier, and it's what production uses too. Docker is an optional local
alternative.

## Option A — Cloud stores (recommended)

1. **Postgres:** create a free database at [Neon](https://neon.tech) → copy its
   connection string (looks like `postgres://user:pass@…neon.tech/db?sslmode=require`).
2. **Redis:** create a free database at [Upstash](https://upstash.com) → copy its
   `rediss://…` URL (TLS).
3. Run the service on your machine, pointing at them:

```bash
cd services/authorize-svc
DATABASE_URL="postgres://…neon.tech/db?sslmode=require" \
REDIS_URL="rediss://…upstash.io:6379" \
go run ./cmd/authorize-svc
```

That's it — no Docker, no WSL, nothing to install beyond Go. The service connects and
serves `/health` on `:8080`.

Apply the migrations once (any `psql`, or Neon's SQL console):

```bash
psql "$DATABASE_URL" -f deploy/migrations/0001_api_keys.sql
psql "$DATABASE_URL" -f deploy/migrations/0002_decisions.sql
```

The audit log (0002) is append-only and works without extra config — sensitive
fields are stored as plaintext until you set `AUTHZ_AUDIT_ENCRYPTION_KEY` (a 32-byte
key in base64 or hex) to turn on field-level encryption of amount/target. See
[docs/audit-log.md](audit-log.md).

## Option B — Docker for local stores (optional)

If you prefer everything local and already have Docker:

```bash
cd deploy && docker compose up -d postgres redis   # just the stores
cd .. && make run                                    # service on the host
```

Or the whole stack (stores + service) in containers:

```bash
make up
```

Docker's WSL disk can grow over time; if you go this route, cap the disk image in
Docker Desktop settings. (This is exactly why cloud is the easier default.)

## Health check

```bash
curl -s http://localhost:8080/health
```

HTTP 200 with `"status":"ok"` and `checks.postgres/redis = "ok"`. If a store is down
you get **503** + `"status":"degraded"` naming the failing check — the service never
reports healthy while blind to a store.

## Configuration

| Env | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | Postgres DSN | local docker |
| `REDIS_URL` | Redis URL (`rediss://` for TLS/Upstash) | local docker |
| `AUTHZ_ADDR` | listen address | `:8080` |
| `AUTHZ_SIGNING_PRIVATE_KEY` | base64/hex Ed25519 seed; empty = generate a dev key at boot | *(empty)* |
| `LOG_LEVEL` | debug/info/warn/error | `info` |

Auth, rate-limit, and signing knobs: see `deploy/.env.example`,
`docs/request-authentication.md`, `docs/rate-limiting.md`.

## Tests (no infra)

```bash
cd services/authorize-svc && go test ./...
```

All unit + integration tests use in-memory fakes for Postgres/Redis, so they pass with
nothing installed. CI additionally runs a `docker compose` smoke test on Linux to prove
real connectivity.

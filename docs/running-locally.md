# Running Locally

## Prerequisites
- Docker + Docker Compose (for Postgres 15 + Redis 7, and the containerized service)
- Go 1.23+ (only if running `authorize-svc` outside Docker)
- `make` optional — Windows users can use `./tasks.ps1 <target>` instead

## One command
From the repo root:

```bash
make up
```

This runs `docker compose -f deploy/docker-compose.yml up -d --build`, which:
1. Starts **Postgres 15** and **Redis 7** with healthchecks.
2. Builds and starts **authorize-svc**, which waits for both to be healthy,
   connects to each, and serves `/health`.

Check it:

```bash
curl -s http://localhost:8080/health
```

Expected: HTTP 200 with JSON like:

```json
{
  "status": "ok",
  "build": { "version": "dev", "commit": "none", "date": "unknown" },
  "checks": { "postgres": "ok", "redis": "ok" },
  "time": "2026-08-28T00:00:00Z"
}
```

If a dependency is down, `/health` returns **503** with `"status": "degraded"`
and the failing check named — the service never reports healthy while blind to a
store.

## Running the service on the host (stores in Docker)
Start only the stores, then run the Go binary locally:

```bash
cd deploy && docker compose up -d postgres redis
cd .. && make run
```

Defaults target `localhost:5432` / `localhost:6379`; override with
`DATABASE_URL`, `REDIS_URL`, `AUTHZ_ADDR`, `LOG_LEVEL`.

## Tests

```bash
make test
```

Health handler tests inject fake dependency checks, so they pass without real
Postgres/Redis. The `docker compose` smoke test in CI covers real connectivity.

## Tear down

```bash
make down          # keep volumes
```

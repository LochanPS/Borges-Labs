# Trust Infrastructure for Autonomous Financial Agents

Deterministic, policy-driven **APPROVE / DENY / REVIEW** authorization middleware
that sits between an AI agent and its payment provider and **never moves, holds,
or settles money**. It answers *"should this agent be allowed to make this
payment?"* inline, in milliseconds, with a signed, auditable explanation.

Canonical specs — read these first:
[PRD.md](PRD.md) · [TRD.md](TRD.md) · [ROADMAP.md](ROADMAP.md) (§A critical fixes).

> **Status: scaffold (ROADMAP Task 0.1).** Builds, boots, connects to Postgres +
> Redis, and serves `/health`. **No authorization business logic yet** — that
> arrives in later phases.

## Monorepo layout

| Path | What | Stack | Status |
|---|---|---|---|
| `services/authorize-svc` | Decision plane — hot path | **Go** (TRD §4) | scaffold ✅ |
| `services/policy-svc` | Control plane — policy authoring/versioning | **TypeScript/Node** ([why](services/policy-svc/README.md)) | placeholder |
| `services/dashboard` | Control-plane UI | Next.js | placeholder |
| `sdks/python`, `sdks/ts` | Thin client SDKs | Python / TS | placeholder |
| `contracts` | OpenAPI + JSON Schema + generated types — **source of truth** | — | frozen in Task 0.2 |
| `deploy` | Local `docker-compose` (Postgres 15 + Redis 7 + service) | — | ✅ |
| `docs` | Runbooks | — | ✅ |

**Two-plane architecture (TRD §1):** the decision plane (Go, stateless, in the
payment path) and the control plane (not in the payment path) fail independently.
The decision plane only reads cached bundles and writes async audit — it never
makes a synchronous call to the control plane.

## Quick start

Requires Docker + Docker Compose. From the repo root:

```bash
make up
```

Then:

```bash
curl -s http://localhost:8080/health
```

→ HTTP **200**, JSON reporting build info and `postgres` / `redis` check status.
Full walkthrough (host-run mode, tests, teardown): [docs/running-locally.md](docs/running-locally.md).

### Tasks (`make <target>`, or `./tasks.ps1 <target>` on Windows)

| Target | Does |
|---|---|
| `up` | Postgres 15 + Redis 7 + authorize-svc, one command |
| `down` | Stop the stack |
| `run` | Run authorize-svc on the host (stores must be reachable) |
| `test` | Go tests |
| `build` | Build the service binary |
| `logs` / `tidy` / `fmt` / `vet` | Tail logs / sync deps / format / static-check |

> **Windows note:** this repo was scaffolded on Windows, where `go`, `docker`,
> and `make` were not installed on the host — so the build/boot were **not run
> locally**. Use Docker Desktop (for `make up`) or WSL, or rely on CI. Everything
> is authored to build and pass in CI (Go 1.23 + Docker on `ubuntu-latest`).

## Observability

Structured **JSON logging from day one** (TRD §18) via Go's `log/slog` — one JSON
line per request and per lifecycle event, to stdout for an aggregator.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) on every push / PR:
- **authorize-svc:** `gofmt` check → `go vet` → build → `go test -race`.
- **compose-smoke:** `docker compose up`, then polls until `/health` returns 200.

## Acceptance (Task 0.1)

- [x] `docker compose up` starts Postgres 15 + Redis 7
- [x] `authorize-svc` boots and connects to both
- [x] `/health` returns 200 (503 + `degraded` when a store is down)
- [x] Build info surfaced (version / commit / date via `-ldflags`)
- [x] Structured JSON logging
- [x] Makefile (`up` / `test` / `run` …) + Windows `tasks.ps1`
- [x] GitHub Actions builds + tests on push
- [x] README documents how to run it

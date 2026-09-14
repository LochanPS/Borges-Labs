# Deploying Trust Infrastructure (Phase 6.1)

End-to-end deploy of the two runtimes:

- **authorize-svc** (Go decision + control plane) → Fly.io or Railway, behind HTTPS,
  on managed Postgres + Redis.
- **dashboard** (Next.js control-plane UI) → Vercel.

The decision plane fails independently of the control plane (TRD §1); deploy them as
two services. Everything below uses managed stores (no self-hosted DB).

---

## 1. Provision managed stores

- **Postgres** — [Neon](https://neon.tech): create a database, copy the
  `postgres://…?sslmode=require` connection string → `DATABASE_URL`.
- **Redis** — [Upstash](https://upstash.com): create a database, copy the
  `rediss://…` (TLS) URL → `REDIS_URL`.

Apply the schema (idempotent):

```bash
DATABASE_URL="postgres://…neon.tech/db?sslmode=require" ./deploy/apply-migrations.sh
```

## 2. Generate the secrets

```bash
# Ed25519 decision-signing seed (32 bytes). Keep this stable across restarts so old
# decisions keep verifying. In production store it in the platform secret manager / KMS.
openssl rand -base64 32          # -> AUTHZ_SIGNING_PRIVATE_KEY

# AES-256-GCM key for field-level audit encryption of amount/target (32 bytes).
openssl rand -base64 32          # -> AUTHZ_AUDIT_ENCRYPTION_KEY
```

## 3. Deploy authorize-svc

The image is built from `services/authorize-svc/Dockerfile` (multi-stage, distroless,
non-root). Build context is the **repo root** (it binds the in-repo contracts module).

### Option A — Fly.io

```bash
fly launch --no-deploy --copy-config --config deploy/fly.toml
fly secrets set \
  DATABASE_URL="postgres://…" \
  REDIS_URL="rediss://…" \
  AUTHZ_SIGNING_PRIVATE_KEY="…" \
  AUTHZ_AUDIT_ENCRYPTION_KEY="…"
fly deploy . --config deploy/fly.toml --dockerfile services/authorize-svc/Dockerfile
```

### Option B — Railway

Point the service at `deploy/railway.json` (Dockerfile builder, `/health` healthcheck),
then set the same four secrets plus `AUTHZ_ADDR=:8080` in the Railway variables UI and
deploy. Add the Neon/Upstash URLs as `DATABASE_URL` / `REDIS_URL`.

### Required env / secrets

| Var | Purpose |
|---|---|
| `DATABASE_URL` | Neon Postgres DSN (secret) |
| `REDIS_URL` | Upstash Redis URL, `rediss://` (secret) |
| `AUTHZ_SIGNING_PRIVATE_KEY` | Ed25519 seed for decision signatures (secret) |
| `AUTHZ_AUDIT_ENCRYPTION_KEY` | AES key for audit field encryption (secret) |
| `AUTHZ_ADDR` | listen address, `:8080` |
| `AUTHZ_CONTROL_PLANE_ENABLED` | `true` to serve `/v1/policies*` |
| `AUTHZ_TRACE_EXPORTER` | `otlp` (+ `OTEL_EXPORTER_OTLP_ENDPOINT`) or empty |

TLS is terminated by the platform ingress; the service also sets HSTS + CSP +
`X-Frame-Options` on every response (defense in depth).

## 4. Mint an admin API key

Keys can be created from the dashboard once it is up, or from the CLI against the DB:

```bash
cd services/authorize-svc
DATABASE_URL="postgres://…" go run ./cmd/authz-keygen \
  -env live -org <org> -tier default -insert            # add -enforce for an enforcing key
```

The dashboard uses one such key server-side to call the control plane; a partner gets
their own key (shadow by default — advisory-first, A#5).

## 5. Deploy the dashboard (Vercel)

Import the repo in Vercel with **Root Directory = `services/dashboard`**
(`vercel.json` is there). Set environment variables:

| Var | Value |
|---|---|
| `AUTHZ_BASE_URL` | the authorize-svc public URL (e.g. `https://trust-infra-authorize.fly.dev`) |
| `AUTHZ_API_KEY` | an admin key from step 4 (server-side only; never `NEXT_PUBLIC_`) |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | Clerk publishable key (optional; enables auth) |
| `CLERK_SECRET_KEY` | Clerk secret key (optional) |

Without the Clerk vars the app runs in dev-bypass mode; add them to enforce sign-in.

## 6. Verify

```bash
curl -s https://<authorize-host>/health      # {"status":"ok", checks: {postgres, redis}}
curl -s https://<authorize-host>/metrics      # Prometheus text (verdicts, latency, rate limits)
```

Open the dashboard `/status` page — it polls `/v1/health` every 5s. Scrape `/metrics`
with Prometheus; alert on latency SLO burn and on enrichment `degraded`.

## 7. Onboard one design partner (the MVP go/no-go)

1. Give the partner a **shadow** key + the SDK (`pip install trust-infra-sdk` /
   `npm i @trust-infra/sdk`).
2. They wrap `authorize()` before their payment call in **shadow mode** — decisions are
   evaluated + audited but never block — for ~2 weeks of real traffic.
3. Review the audit log together in the dashboard.
4. Flip **one** agent's key to enforce (`shadow=false`). That shadow→enforce flip is the
   go/no-go signal for the whole MVP (ROADMAP §6.1).

---

## Notes

- **Never commit secrets.** `DATABASE_URL`, `REDIS_URL`, and both keys are set via the
  platform secret store, not in `fly.toml` / `railway.json` / git.
- **Signing key stability:** rotating `AUTHZ_SIGNING_PRIVATE_KEY` changes the published
  public key; keep the old key published until every decision signed under it has aged
  out of retention (decision-canonicalization.md §4).
- **`/metrics` is unauthenticated** for scraping — restrict it at the network layer
  (private networking / IP allowlist), don't expose it on the public ingress.

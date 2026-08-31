# Rate limiting (authorize-svc)

Three layers defend `POST /v1/authorize` (TRD §11, ROADMAP Task 1.3). Two are in the
app; the third is infrastructure.

## Layer 1 — per-key sliding window (in-app)

A fixed-window counter per `(key_id, minute)` in Redis, incremented with an **atomic
INCR+EXPIRE** (a single Lua eval, so the counter can never be left without a TTL).
Bounds sustained throughput. The ceiling comes from the key's **tier**.

## Layer 2 — per-key burst cap (in-app)

A counter per `(key_id, second)` with a ~1-second TTL, default **≤ 10 req/s**. Bounds
instantaneous spikes even when the per-minute budget has room. Also tier-driven.

Both layers share Redis counters, so a key's limit holds across every decision-plane
instance, not per process. Implementation: `internal/ratelimit`. Tiers:
`ratelimit.DefaultTiers()` (`default` = 60/min, 10/s; `pro`, `free` variants).

On exceed: **HTTP 429** with a **`Retry-After`** header (whole seconds) and an RFC 7807
body (`code: "rate_limited"`). If Redis is unavailable the limiter **fails open**
(allows the request) and logs — a guardrail must not turn a cache blip into a full
outage. (Contrast: the auth nonce check fails *closed*, because a replay we cannot
rule out is a security failure, not a capacity one.)

## Layer 3 — per-IP throttle (infrastructure — NOT in the app)

Per-IP throttling is deliberately **not** implemented in the service. It belongs at
the edge, for concrete reasons:

- The true client IP is only reliable at the edge. Behind a load balancer the app sees
  the LB's address unless it trusts `X-Forwarded-For`, which is spoofable if trusted
  blindly — an in-app IP limit is easy to evade or to mis-fire.
- An IP is not a tenant. IP limits are a blunt anti-abuse / DDoS control (unauthenticated
  floods, scrapers), best applied *before* traffic reaches application compute.
- Edge platforms already do this well and cheaply.

Configure it on whatever fronts the service:

- **Cloudflare** — WAF Rate Limiting rule on the route (e.g. N req/min per IP), or a
  Gateway rule.
- **NGINX / ingress** — `limit_req_zone $binary_remote_addr` + `limit_req`.
- **AWS ALB + WAF** — a WAF `RateBasedStatement` (per source IP).
- **Envoy / API gateway** — the global (per-IP) rate-limit filter.

Recommended starting point: a per-IP limit comfortably above a legitimate single
tenant's expected peak, so it catches floods without clipping real bursts (which
Layer 2 already bounds per key). Keep the app's key-level limits as the precise
control and the IP limit as the coarse shield.

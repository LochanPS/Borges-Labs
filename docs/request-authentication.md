# Request authentication (authorize-svc)

How a caller authenticates to `POST /v1/authorize`. Implemented in
`services/authorize-svc/internal/auth` (TRD §11, ROADMAP Task 1.2).

There are **two different signatures** in this system; do not confuse them:

| Signature | Direction | Algorithm | Purpose |
|---|---|---|---|
| **Request signing** (this doc) | caller → us | **HMAC-SHA256** (symmetric) | Authenticate the caller and bind the request |
| **Decision signing** | us → everyone | **Ed25519** (asymmetric) | Third-party-verifiable audit receipt |

Request signing is symmetric because the caller holds the key. Decision signing is
asymmetric so auditors can verify without any secret (ROADMAP A#1).

## API keys

- 256-bit crypto-random secret, formatted `azn_live_<base32>` / `azn_test_<base32>`.
- The server stores **only `sha256(key)`** (hex). The raw key is never persisted.
- A key is identified by a **public key id** = prefix + first 16 hex chars of
  `sha256(key)` — safe to log and index.
- Verification is a **constant-time** compare (`crypto/subtle`) of `sha256(presented)`
  against the stored hash.
- Key records live in Postgres (`api_keys`, source of truth) fronted by a Redis cache
  (`key_id → record`, 5-min TTL). Revocation should also evict the cache entry
  (`RedisKeyCache.Invalidate`) so "revoke = immediate" holds instead of waiting out
  the TTL.

Mint a key:

```bash
go run ./cmd/authz-keygen -env test -org org_demo -tier default
# add -insert (with DATABASE_URL set) to write it into api_keys
```

## Headers

Every authenticated request carries:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <api_key>` (or `X-Api-Key: <api_key>`) |
| `X-Timestamp` | Unix seconds when the request was signed |
| `X-Nonce` | Unique per request, 8..128 chars |
| `X-Signature` | Lowercase hex HMAC-SHA256 (see below) |

The full key is presented on the wire (over TLS) so the server can recompute the
HMAC using it as the secret while still storing only the hash. A future hardening can
send only the key id if the signature alone must prove possession.

## Canonical signing string

The bytes both sides HMAC, newline-delimited, versioned by the leading label:

```
azn-hmac/1
<HTTP-METHOD, uppercase>
<request path, e.g. /v1/authorize>
<X-Timestamp>
<X-Nonce>
<hex sha256(request body)>
```

```
X-Signature = hex( HMAC-SHA256( key = api_key, msg = canonical_string ) )
```

The body is represented by its SHA-256 so the payload stays small and binary-safe,
and any body tampering breaks the signature. Any change to this format is a breaking
protocol change and must bump the `azn-hmac/1` label. Reference implementation:
`auth.Sign` (server-side verification: `Authenticator.verifySignature`).

## Timestamp skew & replay

- Requests whose `X-Timestamp` differs from server time by more than
  `AUTHZ_HMAC_MAX_SKEW` (default 5m), in either direction, are rejected.
- Each `(key_id, nonce)` is remembered in Redis for `AUTHZ_NONCE_TTL`
  (default 10m, forced to ≥ 2×skew). A reused nonce is rejected as a replay.
- The nonce is recorded **only after the signature verifies**, so an attacker cannot
  exhaust nonces without a valid signature.

## Failure responses (RFC 7807)

| Condition | Status | `code` |
|---|---|---|
| Missing / malformed key, bad signature, skew, unknown key | `401` | `unauthorized` |
| Replayed nonce | `401` | `replay_detected` |
| Revoked key (valid credential) | `403` | `forbidden` |
| Backing store unavailable (fail-closed) | `503` | `auth_unavailable` |
| Rate limit exceeded (Task 1.3) | `429` | `rate_limited` |

401 responses carry `WWW-Authenticate: Bearer`. The 401s are deliberately
indistinguishable in detail so they cannot be used as an oracle. On any store error
the authenticator **fails closed** — a check it cannot perform is a check that failed.

## Config

| Env | Default | Meaning |
|---|---|---|
| `AUTHZ_HMAC_MAX_SKEW` | `5m` | Max timestamp skew |
| `AUTHZ_NONCE_TTL` | `10m` | Nonce memory (≥ 2×skew) |
| `AUTHZ_KEY_CACHE_TTL` | `5m` | Redis key-record cache TTL |

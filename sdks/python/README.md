# trust-infra-sdk (Python)

Thin Python client for the **AI Transaction Authorization Infrastructure** `/v1` API.
It canonicalizes and HMAC-signs every request, verifies the **Ed25519** signature on
each decision against the published public key, and applies an explicit fail-mode.
It **never** turns an upstream failure into a silent `APPROVE` (TRD §10).

Generated/bound from the frozen contract in [`/contracts`](../../contracts) — the same
single source of truth the Go types bind.

## Install

```bash
pip install trust-infra-sdk
```

Runtime dependency: `cryptography` (Ed25519). Everything else is the Python stdlib.

## Three-line integration

```python
from trust_infra import Client

client = Client(api_key="azn_live_...", public_keys=jwks)   # jwks from GET /v1/keys/public
client.authorize(txn).enforce()   # verifies the Ed25519 receipt; raises unless APPROVE
charge(txn)                       # your existing payment call, reached only on APPROVE
```

`txn` is a dict (or an `AuthorizeRequest`) with the
[`authorize-request`](../../contracts/schemas/authorize-request.schema.json) fields:

```python
txn = {
    "agent_id": "procurement-agent-v2",
    "action": "payment.create",
    "amount": "1200.00",          # decimal STRING — never a float
    "currency": "USD",
    "target": {"type": "vendor", "id": "acme-supplies"},
    "idempotency_key": "idem_01HXYZ...",
}
```

A runnable, offline version is in [`examples/quickstart.py`](examples/quickstart.py).

## Shadow mode (the adoption wedge, PRD §9)

```python
decision = client.shadow(txn)     # evaluated + logged, NEVER enforced
log.info("would have been %s", decision.verdict.value)
charge(txn)                       # payment path untouched
```

Flip from `shadow()` to `authorize().enforce()` when you're ready to block. A
decision produced by a shadow-mode key carries `shadow=True`; `.enforce()` honors that
and never blocks on it.

## Methods

| Method | Endpoint | Returns |
|---|---|---|
| `authorize(txn)` | `POST /v1/authorize` | `Decision` (signature verified) |
| `shadow(txn)` | `POST /v1/authorize` | `Decision` (advisory, never enforced) |
| `capture(decision_id)` | `POST /v1/authorize/{id}/capture` | `HoldState` |
| `void(decision_id)` | `POST /v1/authorize/{id}/void` | `HoldState` |
| `verify_decision(dec)` | — (local) | `Decision` with `signature_verified=True` |
| `fetch_public_keys()` | `GET /v1/keys/public` | JWKS dict |

### Verify any decision (no secret needed)

`verify_decision` reproduces the `ti-decision-canon/1` canonical bytes and checks the
Ed25519 signature against the published key — so a customer, auditor, or regulator can
validate a receipt they were handed:

```python
from trust_infra import verify_decision, SignatureVerificationError

try:
    verify_decision(decision_dict, jwks)    # also: client.verify_decision(...)
except SignatureVerificationError:
    ...  # tampered or not ours — do not trust
```

## Fail modes — `on_unavailable`

When the decision plane is unreachable or returns `503`, the SDK applies the policy you
chose. Fail-mode results are **synthetic**, **unsigned**, and flagged `degraded=True` —
they did not come from the service.

| Mode | Behavior when unavailable |
|---|---|
| `FAIL_CLOSED` *(default)* | Synthetic `DENY`. `.enforce()` raises → payment blocked. |
| `FAIL_OPEN` | Synthetic `APPROVE` — **explicit, logged at WARNING, degraded**. Opt-in only. |
| `LOCAL_CACHE` | Replay the last signed decision cached for this `idempotency_key`; on a cache miss, fail **closed** (never open). |

```python
from trust_infra import Client, OnUnavailable
client = Client(api_key="azn_live_...", public_keys=jwks,
                on_unavailable=OnUnavailable.FAIL_CLOSED)
```

The only way to get an `APPROVE` out of an outage is to explicitly choose `FAIL_OPEN`;
there is no code path that silently approves on error.

## Errors (RFC 7807)

Non-2xx responses are parsed from `application/problem+json`
([`error.schema.json`](../../contracts/schemas/error.schema.json)) into typed
exceptions you can `except` on:

`ValidationError` (400/422) · `AuthenticationError` (401) · `ReplayError`
(`replay_detected`) · `ForbiddenError` (403) · `NotFoundError` (404) ·
`ConflictError` (409) · `RateLimitedError` (429, with `.retry_after`) ·
`ServiceUnavailableError` (503). Each carries `.status`, `.title`, `.detail`,
`.code`, and field-level `.errors`. Base class: `ProblemError` → `TrustInfraError`.

A decision whose signature does not verify raises `SignatureVerificationError` and is
never returned as if trustworthy.

## Two signatures, kept distinct (ROADMAP A#1)

| | Direction | Algorithm | Where |
|---|---|---|---|
| **Request auth** | caller → us | HMAC-SHA256 (symmetric) | `X-Signature` header, `azn-hmac/1` |
| **Decision receipt** | us → everyone | Ed25519 (asymmetric) | `Decision.signature`, `ti-decision-canon/1` |

HMAC on the receipt would let any key-holder forge decisions — forbidden. The SDK
rejects a decision signature whose `algorithm` isn't `Ed25519`.

## Configuration

```python
Client(
    api_key,                       # required; azn_live_ / azn_test_
    public_keys=None,              # JWKS dict / list / {kid: Ed25519PublicKey}; auto-fetched if None
    base_url="https://api.trust-infra.dev",
    on_unavailable=OnUnavailable.FAIL_CLOSED,
    timeout=5.0,
    verify_signatures=True,        # verify every signed decision before returning it
    transport=None,                # inject requests/httpx or a fake; default stdlib urllib
    cache=None,                    # MutableMapping for LOCAL_CACHE
)
```

## Development

```bash
pip install -e ".[test]"
pytest
```

Tests cover a real signed-decision verify round-trip, tamper detection, the HMAC
signing string, and every fail mode (including "never silently approves").

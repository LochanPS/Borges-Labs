# Two-phase budget holds (authorize / capture / void)

ROADMAP A#2, Task 3.1. `/v1/authorize` is not a pure read: if a decision consumes
budget it has a side effect, and an APPROVE followed by a *failed* payment would leave
budget consumed for money that never moved. So budget-affecting authorizations are
**two-phase**, the card auth-vs-capture pattern.

## Flow

1. **`POST /v1/authorize`** — evaluates as usual. If the active policy declares a budget
   for the agent and the verdict is a **non-shadow APPROVE**, the decision carries a
   signed `capture_within` obligation and the service places a **hold** (reservation)
   with a TTL. The obligation's `params.hold_ref` is the decision id — the handle for
   the next step.
2. **`POST /v1/authorize/{id}/capture`** — commit the held amount, after the downstream
   payment succeeds. Idempotent.
3. **`POST /v1/authorize/{id}/void`** — release the hold, if the payment failed/aborted.
   Idempotent.
4. **TTL auto-release** — an untouched hold auto-expires at its TTL (`AUTHZ_HOLD_TTL`,
   default 15m) and is released, so a crashed caller cannot leak budget.

Shadow (advisory) decisions and DENY/REVIEW never place a hold — only a binding APPROVE
reserves budget.

## State machine (addressed by the decision id)

```
                 capture
    held ─────────────────────▶ captured   (committed; terminal)
     │  │
     │  └────── void ─────────▶ voided      (released; terminal)
     │
     └──── TTL elapsed ───────▶ expired     (released; terminal)
```

| Action | held | captured | voided | expired | missing |
|---|---|---|---|---|---|
| **capture** | → captured | → captured (idempotent) | **409** | **409** (Redis: 404) | 404 |
| **void** | → voided | **409** | → voided (idempotent) | → voided | 404 |

`capture` after `void` is rejected (409); `void` after `capture` is rejected (409).
These are the two illegal transitions; everything else is idempotent or a release.

## Backing store

Holds live in **Redis**, one hash per hold keyed `hold:<org>:<decision_id>` with an
absolute expiry (`PEXPIREAT`) at the TTL, so release is Redis-native — no sweeper.
Transitions run as Lua scripts for atomicity under concurrent capture/void. An expired
Redis hold's key is evicted, so a later capture/void sees 404 (the released state); the
in-memory test store instead tracks an explicit `expired` state for deterministic tests.

## What Phase 3.1 does *not* do yet

3.1 is the **mechanism**: a durable, idempotent, TTL-bounded lifecycle. The reservation
**arithmetic** — decrementing an atomic budget counter, enforcing the cap so N
concurrent authorizations cannot oversell, and reconciling Redis to Postgres — is
Phase 3.2 (ROADMAP §3.2). Until then a hold records the reservation and its lifecycle
without checking it against a limit.

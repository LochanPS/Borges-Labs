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
| **capture** | → captured | → captured (idempotent) | **409** | **409** | 404 |
| **void** | → voided | **409** | → voided (idempotent) | → voided | 404 |

`capture` after `void` is rejected (409); `void` after `capture` is rejected (409).
These are the two illegal transitions; everything else is idempotent or a release.

## Enforcement — atomic counters & no-oversell (Task 3.2)

A budget is a **stateful predicate evaluated outside the local engine** (A#3): the
engine reserves only after the local rules approve, then folds the result
(`WITHIN_LIMIT` → SATISFIED, `EXCEEDED` → DENIED, `UNAVAILABLE` → fail-closed REVIEW)
into the verdict and signs it.

- **Atomic gate (no oversell).** The reservation is a single **Redis** check-and-add
  (Lua): increment the window counter `budget:<org>:<budget_id>:<window_key>` by the
  amount *iff* `spend_to_date + amount ≤ limit`. Because the check and the increment are
  one atomic server-side step, N concurrent authorizations against one cap can never
  total above the limit. This costs one central round trip per budget-affecting decision
  — the documented price of a hard cap (TRD §17).
- **Windows.** `window_key` is derived from the injected `evaluated_at`: `day`
  (YYYY-MM-DD), `month` (YYYY-MM), or `rolling` (a single bucket, sliding TTL). A new
  period is a new key, so rollover resets the cap. Counter TTLs: day 48h, month 32d,
  rolling 30d.
- **Source of truth + reconciliation.** The Redis counter is the fast gate; the durable
  record is the **Postgres** reservation ledger (`budget_reservations`, migration 0006).
  The reconciler (a) releases TTL-expired held reservations back to the counter — so a
  crashed caller cannot leak budget — and (b) rebuilds a drifted counter from the ledger
  (`counter := Σ held+captured`), e.g. after a Redis restart.
- **Fail closed.** If Redis is unavailable the reserve returns `UNAVAILABLE` and the
  decision fails closed to REVIEW — never a fabricated within-limit (§21).

Money is handled in integer minor units (2 dp); amounts with more than two fractional
digits are rejected so the counter arithmetic stays exact.

Counter transitions vs. hold lifecycle: **reserve** increments; **void** decrements
(exactly once — the ledger reports whether this call performed the release);
**capture** leaves the amount counted (committed spend persists); **expiry** is a
reconciler-driven decrement.

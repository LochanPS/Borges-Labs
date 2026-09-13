"""Client configuration: fail-mode policy and tunable protocol constants."""
from __future__ import annotations

import enum


class OnUnavailable(str, enum.Enum):
    """What the SDK does when the decision plane cannot be reached or returns 503.

    The decision plane deliberately never guesses (OpenAPI 503 "Unavailable: ...
    Never a silent guess"), so the *caller* must state its risk posture. The one
    thing the SDK will NEVER do is swallow an upstream failure into a silent
    APPROVE (TRD §10) -- FAIL_OPEN approvals are explicit, marked ``degraded``,
    unsigned, and logged at WARNING.
    """

    #: Treat an unreachable plane as DENY. Safe default for the payment path.
    FAIL_CLOSED = "FAIL_CLOSED"
    #: Treat an unreachable plane as APPROVE. Explicit, loud, and opt-in only.
    FAIL_OPEN = "FAIL_OPEN"
    #: Replay the last decision cached for this idempotency_key; if none is
    #: cached, fall back to FAIL_CLOSED (never to APPROVE).
    LOCAL_CACHE = "LOCAL_CACHE"


#: Canonicalization scheme label for HMAC request signing (docs/request-authentication.md).
HMAC_SCHEME = "azn-hmac/1"
#: Canonicalization scheme label for Ed25519 decision signatures (docs/decision-canonicalization.md).
DECISION_CANON = "ti-decision-canon/1"
#: Default max clock skew the server tolerates on X-Timestamp (AUTHZ_HMAC_MAX_SKEW).
DEFAULT_MAX_SKEW_SECONDS = 300

"""trust_infra -- Python SDK for the AI Transaction Authorization Infrastructure /v1 API.

One-call integration::

    from trust_infra import Client

    client = Client(api_key="azn_live_...", public_keys=jwks)
    client.authorize(txn).enforce()   # raises unless APPROVE; shadow decisions never block
    charge(...)                       # your existing payment call, reached only on APPROVE

Two signatures, kept distinct (ROADMAP A#1): requests are HMAC-signed (symmetric,
caller holds the key); decisions are Ed25519-signed (asymmetric) and verified here
against the published public key with no shared secret.
"""
from __future__ import annotations

from .client import Client
from .config import (
    DECISION_CANON,
    DEFAULT_MAX_SKEW_SECONDS,
    HMAC_SCHEME,
    OnUnavailable,
)
from .exceptions import (
    AuthenticationError,
    ConflictError,
    DecisionDeniedError,
    ForbiddenError,
    NotFoundError,
    ProblemError,
    RateLimitedError,
    ReplayError,
    ServiceUnavailableError,
    SignatureVerificationError,
    TransportError,
    TrustInfraError,
    UpstreamUnavailableError,
    ValidationError,
)
from .models import (
    AuthorizeRequest,
    Counter,
    CounterSnapshot,
    Decision,
    Explanation,
    HoldState,
    HoldStateName,
    MatchedRule,
    Obligation,
    PredicateResult,
    Signature,
    Target,
    Verdict,
)
from .verify import verify_decision

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "Client",
    "OnUnavailable",
    "HMAC_SCHEME",
    "DECISION_CANON",
    "DEFAULT_MAX_SKEW_SECONDS",
    # verification
    "verify_decision",
    # models
    "AuthorizeRequest",
    "Target",
    "Counter",
    "CounterSnapshot",
    "Decision",
    "Explanation",
    "MatchedRule",
    "Obligation",
    "Signature",
    "HoldState",
    "HoldStateName",
    "Verdict",
    "PredicateResult",
    # exceptions
    "TrustInfraError",
    "ProblemError",
    "ValidationError",
    "AuthenticationError",
    "ReplayError",
    "ForbiddenError",
    "NotFoundError",
    "ConflictError",
    "RateLimitedError",
    "ServiceUnavailableError",
    "TransportError",
    "UpstreamUnavailableError",
    "SignatureVerificationError",
    "DecisionDeniedError",
]

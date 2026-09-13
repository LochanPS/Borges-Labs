"""Typed exception hierarchy.

API errors mirror RFC 7807 Problem Details (contracts/schemas/error.schema.json):
every non-2xx carries ``type``, ``title``, ``status``, and optionally ``detail``,
``instance``, ``code``, and field-level ``errors``. The SDK parses that body into a
:class:`ProblemError` subclass chosen by HTTP status, so callers ``except`` on a type
rather than string-matching prose.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class TrustInfraError(Exception):
    """Base class for every error raised by the SDK."""


# --------------------------------------------------------------------------- #
# RFC 7807 problem responses
# --------------------------------------------------------------------------- #
class ProblemError(TrustInfraError):
    """An RFC 7807 ``application/problem+json`` response from the API.

    Attributes mirror error.schema.json so callers can inspect the structured
    problem instead of parsing the message.
    """

    #: HTTP status this subclass represents, or None for the generic base.
    status_code: Optional[int] = None

    def __init__(
        self,
        *,
        type: str = "about:blank",
        title: str = "",
        status: int = 0,
        detail: Optional[str] = None,
        instance: Optional[str] = None,
        code: Optional[str] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
        retry_after: Optional[int] = None,
        raw: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.type = type
        self.title = title
        self.status = status
        self.detail = detail
        self.instance = instance
        self.code = code
        self.errors = errors or []
        self.retry_after = retry_after
        self.raw = raw or {}
        message = f"{status} {title}" + (f": {detail}" if detail else "")
        super().__init__(message.strip())

    @classmethod
    def from_problem(
        cls,
        problem: Dict[str, Any],
        *,
        retry_after: Optional[int] = None,
    ) -> "ProblemError":
        """Build the most specific ProblemError subclass for a problem body."""
        status = int(problem.get("status", 0) or 0)
        code = problem.get("code")
        subclass = _select_problem_class(status, code)
        return subclass(
            type=problem.get("type", "about:blank"),
            title=problem.get("title", ""),
            status=status,
            detail=problem.get("detail"),
            instance=problem.get("instance"),
            code=code,
            errors=problem.get("errors"),
            retry_after=retry_after,
            raw=problem,
        )


class ValidationError(ProblemError):
    """400/422 -- malformed or semantically invalid request. See ``errors`` for fields."""
    status_code = 400


class AuthenticationError(ProblemError):
    """401 -- missing/invalid API key, bad HMAC signature, or timestamp skew."""
    status_code = 401


class ReplayError(AuthenticationError):
    """401/409 with ``code == replay_detected`` -- the nonce was already seen."""


class ForbiddenError(ProblemError):
    """403 -- key revoked or lacks scope."""
    status_code = 403


class NotFoundError(ProblemError):
    """404 -- no such resource."""
    status_code = 404


class ConflictError(ProblemError):
    """409 -- illegal state transition (e.g. capturing a voided/expired hold)."""
    status_code = 409


class RateLimitedError(ProblemError):
    """429 -- per-key rate/burst limit exceeded. See :attr:`retry_after`."""
    status_code = 429


class ServiceUnavailableError(ProblemError):
    """503 -- the decision plane could not serve. Triggers the fail-mode policy."""
    status_code = 503


def _select_problem_class(status: int, code: Optional[str]) -> type:
    if code == "replay_detected":
        return ReplayError
    return {
        400: ValidationError,
        401: AuthenticationError,
        403: ForbiddenError,
        404: NotFoundError,
        409: ConflictError,
        422: ValidationError,
        429: RateLimitedError,
        503: ServiceUnavailableError,
    }.get(status, ProblemError)


# --------------------------------------------------------------------------- #
# Transport / availability
# --------------------------------------------------------------------------- #
class TransportError(TrustInfraError):
    """Network failure, timeout, or other I/O error reaching the decision plane.

    Together with a 503 ``ServiceUnavailableError`` this is what the fail-mode
    policy (:class:`~trust_infra.config.OnUnavailable`) reacts to.
    """


class UpstreamUnavailableError(TrustInfraError):
    """Raised (rather than guessing) when the plane is unavailable and no fail-mode
    can produce a decision -- e.g. LOCAL_CACHE miss would otherwise be ambiguous.

    Never surfaced when a synthetic fail-mode decision is returned instead.
    """


# --------------------------------------------------------------------------- #
# Signature verification
# --------------------------------------------------------------------------- #
class SignatureVerificationError(TrustInfraError):
    """The Ed25519 signature on a Decision did not verify against the published key.

    A decision that fails this check is NOT trustworthy and must not be enforced.
    """


# --------------------------------------------------------------------------- #
# Enforcement
# --------------------------------------------------------------------------- #
class DecisionDeniedError(TrustInfraError):
    """Raised by ``Decision.enforce()`` when the verdict is not APPROVE.

    Carries the decision so callers can read the explanation / obligations.
    """

    def __init__(self, decision: Any) -> None:
        self.decision = decision
        verdict = getattr(decision, "verdict", "?")
        summary = ""
        explanation = getattr(decision, "explanation", None)
        if explanation is not None:
            summary = getattr(explanation, "summary", "") or ""
        super().__init__(f"transaction not approved (verdict={verdict}): {summary}".strip())

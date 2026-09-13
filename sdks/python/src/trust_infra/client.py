"""The synchronous client: one-call authorize/shadow plus capture/void and
third-party-style decision verification.

Responsibilities (TRD §10, "thin"): canonicalize + HMAC-sign each request, attach
nonce + timestamp, call the API, verify the Ed25519 decision signature, and apply the
explicit ``on_unavailable`` fail-mode. It NEVER turns an upstream failure into a
silent APPROVE.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, MutableMapping, Optional, Union

from . import canonical
from .config import OnUnavailable
from .exceptions import (
    ProblemError,
    ServiceUnavailableError,
    SignatureVerificationError,
    TransportError,
)
from .models import AuthorizeRequest, Decision, Explanation, HoldState, Verdict
from .transport import Response, Transport, UrllibTransport
from .verify import PublicKeys, verify_decision as _verify_decision

log = logging.getLogger("trust_infra")

Txn = Union[AuthorizeRequest, Dict[str, Any]]


class Client:
    """Client for the AI Transaction Authorization Infrastructure /v1 API.

    Parameters
    ----------
    api_key:
        Per-key secret, ``azn_live_...`` / ``azn_test_...``. Used as the HMAC key and
        sent on the wire over TLS; only its SHA-256 is stored server-side.
    public_keys:
        Published Ed25519 verification keys (a JWKS dict ``{"keys": [...]}``, a bare
        list of JWKs, or a ``{key_id: Ed25519PublicKey}`` mapping). If omitted, the
        client fetches them from ``GET /v1/keys/public`` on first need and caches them.
    base_url:
        API origin. Defaults to production.
    on_unavailable:
        Fail-mode policy when the plane is unreachable or returns 503. Defaults to
        ``FAIL_CLOSED``.
    verify_signatures:
        When True (default) every signed decision's Ed25519 signature is verified
        before it is returned; a bad signature raises ``SignatureVerificationError``.
    """

    def __init__(
        self,
        api_key: str,
        *,
        public_keys: Optional[PublicKeys] = None,
        base_url: str = "https://api.trust-infra.dev",
        on_unavailable: OnUnavailable = OnUnavailable.FAIL_CLOSED,
        timeout: float = 5.0,
        verify_signatures: bool = True,
        transport: Optional[Transport] = None,
        cache: Optional[MutableMapping[str, Decision]] = None,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(16),
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.on_unavailable = OnUnavailable(on_unavailable)
        self.timeout = timeout
        self.verify_signatures = verify_signatures
        self._transport = transport or UrllibTransport()
        self._cache: MutableMapping[str, Decision] = cache if cache is not None else {}
        self._clock = clock
        self._nonce = nonce_factory
        self._public_keys = public_keys

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def authorize(self, txn: Txn) -> Decision:
        """Evaluate ``txn`` and return a verified, enforceable Decision.

        Typical use enforces the verdict before the real payment call::

            client.authorize(txn).enforce()   # raises DecisionDeniedError unless APPROVE
            charge(...)                        # only reached on APPROVE
        """
        return self._authorize(txn)

    def shadow(self, txn: Txn) -> Decision:
        """Evaluate ``txn`` in shadow/observe-only mode: the decision is returned and
        logged but is **never** enforced, removing adoption risk (PRD §9).

        Returns the same Decision ``authorize`` would, so you can log/compare verdicts
        while keeping the real payment path untouched. Flip to :meth:`authorize` +
        ``enforce()`` when ready.
        """
        decision = self._authorize(txn)
        log.info(
            "shadow decision %s verdict=%s (advisory, not enforced)",
            decision.decision_id,
            decision.verdict.value,
        )
        return decision

    def capture(self, decision_id: str) -> HoldState:
        """Commit the budget hold an APPROVE placed (two-phase, A#2). Call after the
        downstream payment succeeds. POST /v1/authorize/{id}/capture."""
        data = self._request("POST", f"/v1/authorize/{decision_id}/capture")
        return HoldState.from_dict(data)

    def void(self, decision_id: str) -> HoldState:
        """Release the budget hold an APPROVE placed (two-phase, A#2). Call if the
        downstream payment failed or was aborted. POST /v1/authorize/{id}/void."""
        data = self._request("POST", f"/v1/authorize/{decision_id}/void")
        return HoldState.from_dict(data)

    def verify_decision(self, decision: Union[Decision, Dict[str, Any]]) -> Decision:
        """Verify a Decision's Ed25519 signature against the published public key.

        Works for any decision the caller holds -- including one fetched from the audit
        log or handed over by a third party -- not just ones this client produced.
        Raises ``SignatureVerificationError`` on any failure; returns the Decision with
        ``signature_verified = True`` on success.
        """
        return _verify_decision(decision, self._resolve_public_keys())

    def fetch_public_keys(self) -> Dict[str, Any]:
        """GET /v1/keys/public (unauthenticated JWKS) and cache it on the client."""
        resp = self._transport.send(
            "GET",
            f"{self.base_url}/v1/keys/public",
            {"Accept": "application/json"},
            b"",
            self.timeout,
        )
        if resp.status != 200:
            raise self._problem_from_response(resp)
        jwks = json.loads(resp.body.decode("utf-8"))
        self._public_keys = jwks
        return jwks

    # ------------------------------------------------------------------ #
    # Authorize core + fail-mode handling
    # ------------------------------------------------------------------ #
    def _authorize(self, txn: Txn) -> Decision:
        req = AuthorizeRequest.coerce(txn)
        try:
            data = self._request("POST", "/v1/authorize", req.to_dict())
        except (TransportError, ServiceUnavailableError) as exc:
            return self._handle_unavailable(req, exc)

        decision = Decision.from_dict(data)
        if self.verify_signatures and decision.signature is not None:
            # A signature that does not verify is a hard failure -- never returned as
            # if it were trustworthy.
            decision = _verify_decision(decision, self._resolve_public_keys())
        if self.on_unavailable is OnUnavailable.LOCAL_CACHE:
            # Only real, signed decisions seed the cache LOCAL_CACHE later replays.
            self._cache[req.idempotency_key] = decision
        return decision

    def _handle_unavailable(self, req: AuthorizeRequest, cause: Exception) -> Decision:
        mode = self.on_unavailable
        if mode is OnUnavailable.LOCAL_CACHE:
            cached = self._cache.get(req.idempotency_key)
            if cached is not None:
                log.warning(
                    "decision plane unavailable (%s); serving cached decision %s for idempotency_key=%s",
                    cause,
                    cached.decision_id,
                    req.idempotency_key,
                )
                return _mark_cached(cached)
            log.warning(
                "decision plane unavailable (%s); LOCAL_CACHE miss for idempotency_key=%s; failing closed (DENY)",
                cause,
                req.idempotency_key,
            )
            return self._synthetic(
                Verdict.DENY,
                f"Decision plane unavailable and no cached decision for this idempotency_key; "
                f"failing closed (DENY). Cause: {cause}",
            )

        if mode is OnUnavailable.FAIL_OPEN:
            # Explicit, loud, degraded, unsigned -- the opposite of a silent approve.
            log.warning(
                "decision plane unavailable (%s); on_unavailable=FAIL_OPEN -> returning an "
                "UNSIGNED, DEGRADED synthetic APPROVE. This approval did not come from the "
                "service and is not auditable.",
                cause,
            )
            return self._synthetic(
                Verdict.APPROVE,
                f"Decision plane unavailable; failing OPEN (APPROVE) per on_unavailable=FAIL_OPEN. "
                f"Unsigned, degraded, not an audit receipt. Cause: {cause}",
            )

        # FAIL_CLOSED (default).
        log.warning(
            "decision plane unavailable (%s); on_unavailable=FAIL_CLOSED -> DENY",
            cause,
        )
        return self._synthetic(
            Verdict.DENY,
            f"Decision plane unavailable; failing closed (DENY) per on_unavailable=FAIL_CLOSED. "
            f"Cause: {cause}",
        )

    def _synthetic(self, verdict: Verdict, summary: str) -> Decision:
        """Locally synthesized fail-mode decision. Marked ``degraded``, never signed."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return Decision(
            decision_id=f"local_{secrets.token_hex(8)}",
            verdict=verdict,
            policy_version_hash="",
            explanation=Explanation(summary=summary, matched_rules=[]),
            obligations=[],
            evaluated_at=now,
            signature=None,
            latency_ms=None,
            shadow=False,
            signature_verified=False,
            degraded=True,
        )

    # ------------------------------------------------------------------ #
    # Signed HTTP
    # ------------------------------------------------------------------ #
    def _request(
        self,
        method: str,
        path: str,
        body_obj: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        body = (
            json.dumps(body_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if body_obj is not None
            else b""
        )
        timestamp = str(int(self._clock()))  # Unix seconds (docs/request-authentication.md)
        nonce = self._nonce()
        signing_string = canonical.request_signing_string(method, path, timestamp, nonce, body)
        signature = hmac.new(
            self.api_key.encode("utf-8"), signing_string, hashlib.sha256
        ).hexdigest()

        headers = {
            "X-Api-Key": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
            "Accept": "application/json",
        }
        if body:
            headers["Content-Type"] = "application/json"
        if body_obj and "idempotency_key" in body_obj:
            headers["Idempotency-Key"] = body_obj["idempotency_key"]

        resp = self._transport.send(method, f"{self.base_url}{path}", headers, body, self.timeout)
        if 200 <= resp.status < 300:
            return json.loads(resp.body.decode("utf-8")) if resp.body else {}
        raise self._problem_from_response(resp)

    def _problem_from_response(self, resp: Response) -> ProblemError:
        try:
            problem = json.loads(resp.body.decode("utf-8")) if resp.body else {}
        except (ValueError, UnicodeDecodeError):
            problem = {}
        problem.setdefault("status", resp.status)
        problem.setdefault("title", f"HTTP {resp.status}")
        retry_after = resp.headers.get("retry-after")
        return ProblemError.from_problem(
            problem, retry_after=int(retry_after) if retry_after and retry_after.isdigit() else None
        )

    def _resolve_public_keys(self) -> PublicKeys:
        if self._public_keys is None:
            self.fetch_public_keys()
        assert self._public_keys is not None
        return self._public_keys


def _mark_cached(decision: Decision) -> Decision:
    import copy

    clone = copy.deepcopy(decision)
    clone.served_from_cache = True
    clone.degraded = True
    return clone

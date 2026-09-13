"""Typed models mirroring the frozen /contracts JSON Schemas.

These dataclasses are the Python binding of contracts/schemas/*.json and the
OpenAPI component schemas -- the same single-source-of-truth wire shape the Go
types (contracts/gen/go) bind. Field names, optionality, and enums mirror the
schemas exactly. Money is a ``str`` (never a float) to preserve exact precision
and a stable signing form.

These are kept in lockstep with contracts/schemas; when the contract changes, update
this module to match. ``tests/`` validate against the committed contract examples, so a
drift from the schema shows up as a test failure.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class Verdict(str, enum.Enum):
    APPROVE = "APPROVE"
    DENY = "DENY"
    REVIEW = "REVIEW"


class PredicateResult(str, enum.Enum):
    SATISFIED = "SATISFIED"
    DENIED = "DENIED"
    REVIEW = "REVIEW"
    UNAVAILABLE = "UNAVAILABLE"


class HoldStateName(str, enum.Enum):
    HELD = "held"
    CAPTURED = "captured"
    VOIDED = "voided"
    EXPIRED = "expired"


def _enum_value(v: Any) -> Any:
    return v.value if isinstance(v, enum.Enum) else v


# --------------------------------------------------------------------------- #
# Request side (authorize-request.schema.json + common.schema.json)
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """Counterparty/resource the action targets (common.schema.json#/$defs/Target)."""

    type: str  # vendor | account | address | internal | unknown
    id: str

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "id": self.id}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Target":
        return cls(type=d["type"], id=d["id"])


@dataclass
class Counter:
    id: str
    window: str  # day | month | rolling
    spend_to_date: str
    limit: str
    currency: str
    window_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "id": self.id,
            "window": self.window,
            "spend_to_date": self.spend_to_date,
            "limit": self.limit,
            "currency": self.currency,
        }
        if self.window_key is not None:
            out["window_key"] = self.window_key
        return out


@dataclass
class CounterSnapshot:
    as_of: str
    counters: List[Counter] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"as_of": self.as_of, "counters": [c.to_dict() for c in self.counters]}


@dataclass
class AuthorizeRequest:
    """Body of POST /v1/authorize (authorize-request.schema.json).

    ``evaluated_at`` and ``counter_snapshot`` are orchestrator-injected; clients
    should not set them.
    """

    agent_id: str
    action: str
    amount: str
    currency: str
    target: Target
    idempotency_key: str
    jurisdiction: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    evaluated_at: Optional[str] = None
    counter_snapshot: Optional[CounterSnapshot] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "action": self.action,
            "amount": self.amount,
            "currency": self.currency,
            "target": self.target.to_dict(),
            "idempotency_key": self.idempotency_key,
        }
        if self.jurisdiction is not None:
            out["jurisdiction"] = self.jurisdiction
        if self.context is not None:
            out["context"] = self.context
        if self.evaluated_at is not None:
            out["evaluated_at"] = self.evaluated_at
        if self.counter_snapshot is not None:
            out["counter_snapshot"] = self.counter_snapshot.to_dict()
        return out

    @classmethod
    def coerce(cls, txn: "AuthorizeRequest | Dict[str, Any]") -> "AuthorizeRequest":
        """Accept either a model or a plain dict and normalize to a model."""
        if isinstance(txn, AuthorizeRequest):
            return txn
        d = dict(txn)
        target = d["target"]
        snap = d.get("counter_snapshot")
        return cls(
            agent_id=d["agent_id"],
            action=d["action"],
            amount=d["amount"],
            currency=d["currency"],
            target=target if isinstance(target, Target) else Target.from_dict(target),
            idempotency_key=d["idempotency_key"],
            jurisdiction=d.get("jurisdiction"),
            context=d.get("context"),
            evaluated_at=d.get("evaluated_at"),
            counter_snapshot=(
                CounterSnapshot(
                    as_of=snap["as_of"],
                    counters=[
                        c if isinstance(c, Counter) else Counter(**c)
                        for c in snap.get("counters", [])
                    ],
                )
                if isinstance(snap, dict)
                else snap
            ),
        )


# --------------------------------------------------------------------------- #
# Decision side (decision.schema.json + common.schema.json)
# --------------------------------------------------------------------------- #
@dataclass
class MatchedRule:
    rule_id: str
    type: str
    result: PredicateResult
    detail: str
    evidence: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MatchedRule":
        return cls(
            rule_id=d["rule_id"],
            type=d["type"],
            result=PredicateResult(d["result"]),
            detail=d["detail"],
            evidence=d.get("evidence"),
        )


@dataclass
class Explanation:
    summary: str
    matched_rules: List[MatchedRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Explanation":
        return cls(
            summary=d["summary"],
            matched_rules=[MatchedRule.from_dict(r) for r in d.get("matched_rules", [])],
        )


@dataclass
class Obligation:
    type: str
    detail: Optional[str] = None
    params: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Obligation":
        return cls(type=d["type"], detail=d.get("detail"), params=d.get("params"))


@dataclass
class Signature:
    algorithm: str
    key_id: str
    value: str
    canonicalization: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Signature":
        return cls(
            algorithm=d["algorithm"],
            key_id=d["key_id"],
            value=d["value"],
            canonicalization=d["canonicalization"],
        )


@dataclass
class Decision:
    """An authorization decision (decision.schema.json).

    Also carries SDK-local, non-wire annotations describing how it was obtained:

    * :attr:`signature_verified` -- set True once :meth:`verify` / the client has
      validated the Ed25519 signature; None when unverified.
    * :attr:`degraded` -- True for a locally synthesized fail-mode decision that did
      NOT come from the plane (see :class:`~trust_infra.config.OnUnavailable`).
    * :attr:`served_from_cache` -- True when replayed from the LOCAL_CACHE store.

    A degraded decision has no ``signature`` and must be understood as a client-side
    fallback, never a signed receipt.
    """

    decision_id: str
    verdict: Verdict
    policy_version_hash: str
    explanation: Explanation
    obligations: List[Obligation]
    evaluated_at: str
    signature: Optional[Signature] = None
    latency_ms: Optional[int] = None
    shadow: bool = False
    record_hash: Optional[str] = None

    # SDK-local annotations (never part of the wire/signed bytes).
    signature_verified: Optional[bool] = None
    degraded: bool = False
    served_from_cache: bool = False

    # ------------------------------------------------------------------ #
    # Enforcement helpers
    # ------------------------------------------------------------------ #
    @property
    def approved(self) -> bool:
        """True only for an enforceable APPROVE. A shadow/advisory decision is never
        enforceable, so this is False for it regardless of verdict."""
        return self.verdict == Verdict.APPROVE and not self.shadow

    def enforce(self) -> "Decision":
        """Raise :class:`DecisionDeniedError` unless the verdict is an enforceable APPROVE.

        A shadow/advisory decision is never enforced: this logs and returns without
        blocking (shadow mode is observe-only, PRD §9). Returns ``self`` so it chains.
        """
        from .exceptions import DecisionDeniedError  # local import avoids a cycle

        if self.shadow:
            import logging

            logging.getLogger("trust_infra").info(
                "shadow decision %s (verdict=%s) not enforced (advisory)",
                self.decision_id,
                self.verdict.value,
            )
            return self
        if self.verdict != Verdict.APPROVE:
            raise DecisionDeniedError(self)
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Serialize back to the wire shape (for re-signing/verification round-trips)."""
        out: Dict[str, Any] = {
            "decision_id": self.decision_id,
            "verdict": _enum_value(self.verdict),
            "policy_version_hash": self.policy_version_hash,
            "explanation": {
                "summary": self.explanation.summary,
                "matched_rules": [
                    {
                        "rule_id": r.rule_id,
                        "type": r.type,
                        "result": _enum_value(r.result),
                        "detail": r.detail,
                        **({"evidence": r.evidence} if r.evidence is not None else {}),
                    }
                    for r in self.explanation.matched_rules
                ],
            },
            "obligations": [
                {
                    "type": o.type,
                    **({"detail": o.detail} if o.detail is not None else {}),
                    **({"params": o.params} if o.params is not None else {}),
                }
                for o in self.obligations
            ],
            "evaluated_at": self.evaluated_at,
        }
        if self.latency_ms is not None:
            out["latency_ms"] = self.latency_ms
        if self.shadow:
            out["shadow"] = True
        if self.record_hash is not None:
            out["record_hash"] = self.record_hash
        if self.signature is not None:
            out["signature"] = {
                "algorithm": self.signature.algorithm,
                "key_id": self.signature.key_id,
                "value": self.signature.value,
                "canonicalization": self.signature.canonicalization,
            }
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Decision":
        sig = d.get("signature")
        return cls(
            decision_id=d["decision_id"],
            verdict=Verdict(d["verdict"]),
            policy_version_hash=d["policy_version_hash"],
            explanation=Explanation.from_dict(d["explanation"]),
            obligations=[Obligation.from_dict(o) for o in d.get("obligations", [])],
            evaluated_at=d["evaluated_at"],
            signature=Signature.from_dict(sig) if sig else None,
            latency_ms=d.get("latency_ms"),
            shadow=bool(d.get("shadow", False)),
            record_hash=d.get("record_hash"),
            signature_verified=d.get("signature_verified"),
        )


@dataclass
class HoldState:
    """Budget-hold state after capture/void (OpenAPI components/schemas/HoldState)."""

    decision_id: str
    state: HoldStateName
    budget_id: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    expires_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HoldState":
        return cls(
            decision_id=d["decision_id"],
            state=HoldStateName(d["state"]),
            budget_id=d.get("budget_id"),
            amount=d.get("amount"),
            currency=d.get("currency"),
            expires_at=d.get("expires_at"),
        )

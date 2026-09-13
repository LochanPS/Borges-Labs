"""Shared test helpers: a fake transport and a real Ed25519 decision signer.

The signer lets tests prove verify_decision against a *real* signature (acceptance
criterion), without any network or server.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trust_infra import canonical
from trust_infra.transport import Response


def make_keypair() -> Tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, raw_pub


def jwks_for(raw_pub: bytes, key_id: str, status: str = "active") -> Dict[str, Any]:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": key_id,
                "x": canonical.b64url_encode(raw_pub),
                "use": "sig",
                "status": status,
            }
        ]
    }


def sign_decision(decision: Dict[str, Any], priv: Ed25519PrivateKey, key_id: str) -> Dict[str, Any]:
    """Attach a real ti-decision-canon/1 Ed25519 signature to a decision dict."""
    message = canonical.decision_signing_bytes(decision)
    value = canonical.b64url_encode(priv.sign(message))
    signed = dict(decision)
    signed["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": value,
        "canonicalization": "ti-decision-canon/1",
    }
    return signed


def sample_decision(verdict: str = "APPROVE") -> Dict[str, Any]:
    return {
        "decision_id": "01HXYZ8K3M9QF0R7S2T4V6W8XA",
        "verdict": verdict,
        "policy_version_hash": "polv_9f2a1c7e4b5d6a8f0c1e2d3b4a5f6e7d",
        "explanation": {
            "summary": "All rules satisfied.",
            "matched_rules": [
                {
                    "rule_id": "per_txn_5k",
                    "type": "per_transaction_limit",
                    "result": "SATISFIED",
                    "detail": "amount=1200.00 <= per_transaction_limit=5000.00 USD",
                    "evidence": {"amount": "1200.00", "limit": "5000.00", "currency": "USD"},
                }
            ],
        },
        "obligations": [],
        "latency_ms": 7,
        "evaluated_at": "2026-08-27T10:32:11Z",
    }


def sample_txn() -> Dict[str, Any]:
    return {
        "agent_id": "procurement-agent-v2",
        "action": "payment.create",
        "amount": "1200.00",
        "currency": "USD",
        "target": {"type": "vendor", "id": "acme-supplies"},
        "jurisdiction": "US",
        "idempotency_key": "idem_01HXYZ8K3M9QF0R7S2T4V6W8XA",
    }


class FakeTransport:
    """Scripted transport. Each queued item is either a ``Response`` to return or an
    ``Exception`` to raise (to simulate network failure)."""

    def __init__(self, script: Optional[List[Any]] = None) -> None:
        self.script: List[Any] = list(script or [])
        self.calls: List[Dict[str, Any]] = []

    def queue(self, item: Any) -> "FakeTransport":
        self.script.append(item)
        return self

    def send(self, method, url, headers, body, timeout) -> Response:
        self.calls.append(
            {"method": method, "url": url, "headers": dict(headers), "body": body}
        )
        if not self.script:
            raise AssertionError(f"FakeTransport got an unscripted call: {method} {url}")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def json_response(status: int, payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> Response:
    import json

    return Response(
        status=status,
        headers=headers or {},
        body=json.dumps(payload).encode("utf-8"),
    )

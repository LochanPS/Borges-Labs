#!/usr/bin/env python3
"""
Free demo agent — see the authorization product working end to end.

Simulates an AI procurement agent making a stream of transactions through the Python
SDK. Each is authorized BEFORE the (mock) payment; the agent enforces the verdict.

Two modes:
  * mock (default): no backend needed. A local Ed25519 signer stands in for the
    decision plane and applies simple rules, returning REAL signed decisions — so the
    SDK's signature verification genuinely runs and passes.
  * live: point at a running authorize-svc with a key.

Usage:
  python examples/demo-agent/agent.py                 # mock
  python examples/demo-agent/agent.py --count 12
  python examples/demo-agent/agent.py --base-url https://host --api-key azn_test_... [--shadow]

Requires the Python SDK's one dependency (cryptography). From a source checkout this
script adds sdks/python/src to the path automatically.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

# Run from a source checkout without installing the SDK.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO, "sdks", "python", "src"))

from trust_infra import Client, DecisionDeniedError, OnUnavailable, canonical  # noqa: E402
from trust_infra.transport import Response  # noqa: E402


# --------------------------------------------------------------------------- #
# A small, illustrative workload: what a procurement agent might attempt.
# --------------------------------------------------------------------------- #
@dataclass
class Txn:
    amount: str
    vendor: str
    note: str


WORKLOAD = [
    Txn("1200.00", "acme-supplies", "office chairs"),
    Txn("480.00", "acme-supplies", "cables"),
    Txn("5200.00", "globex", "annual software (over per-txn limit)"),
    Txn("9000.00", "globex", "server rack (over budget)"),
    Txn("300.00", "sketchy-vendor", "unknown vendor"),
    Txn("2500.00", "acme-supplies", "monitors"),
]


def to_request(agent_id: str, t: Txn, i: int) -> dict:
    return {
        "agent_id": agent_id,
        "action": "payment.create",
        "amount": t.amount,
        "currency": "USD",
        "target": {"type": "vendor", "id": t.vendor},
        "idempotency_key": f"demo_{agent_id}_{i:04d}",
    }


# --------------------------------------------------------------------------- #
# Mock decision plane: a local Ed25519 signer + simple rules. Produces REAL signed
# decisions so client-side verification actually runs.
# --------------------------------------------------------------------------- #
class MockPlane:
    ALLOWED = {"acme-supplies", "globex"}
    PER_TXN = 5000.0
    REVIEW_CEILING = 8000.0

    def __init__(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self._priv = Ed25519PrivateKey.generate()
        raw = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "demo", "x": canonical.b64url_encode(raw), "use": "sig", "status": "active"}]}

    def _evaluate(self, req: dict) -> dict:
        amt = float(req["amount"])
        vendor = req["target"]["id"]
        if vendor not in self.ALLOWED:
            return _decision(req, "DENY", "vendor_blocklist", "DENIED", f"vendor '{vendor}' is not on the allowlist")
        if amt > self.REVIEW_CEILING:
            return _decision(req, "DENY", "monthly_budget", "DENIED", f"amount={req['amount']} exceeds the monthly budget")
        if amt > self.PER_TXN:
            return _decision(req, "REVIEW", "per_txn_5k", "REVIEW", f"amount={req['amount']} > per_transaction_limit=5000.00 USD; step-up required")
        return _decision(req, "APPROVE", "per_txn_5k", "SATISFIED", f"amount={req['amount']} <= per_transaction_limit=5000.00 USD")

    def send(self, method, url, headers, body, timeout) -> Response:
        req = json.loads(body.decode("utf-8")) if body else {}
        decision = self._evaluate(req)
        value = canonical.b64url_encode(self._priv.sign(canonical.decision_signing_bytes(decision)))
        decision["signature"] = {"algorithm": "Ed25519", "key_id": "demo", "value": value, "canonicalization": "ti-decision-canon/1"}
        return Response(200, {}, json.dumps(decision).encode("utf-8"))


def _decision(req: dict, verdict: str, rule_id: str, result: str, detail: str) -> dict:
    return {
        "decision_id": "01HXYZ" + req["idempotency_key"][-8:].upper().replace("_", "0"),
        "verdict": verdict,
        "policy_version_hash": "polv_demo",
        "explanation": {"summary": detail, "matched_rules": [
            {"rule_id": rule_id, "type": "per_transaction_limit", "result": result, "detail": detail}
        ]},
        "obligations": [] if verdict != "APPROVE" else [{"type": "capture_within", "detail": "capture after payment", "params": {"ttl_seconds": 120}}],
        "evaluated_at": "2026-09-15T10:00:00Z",
    }


def charge(req: dict) -> None:
    print(f"      -> charged {req['amount']} {req['currency']} to {req['target']['id']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Free demo agent for the authorization product.")
    ap.add_argument("--base-url", help="authorize-svc URL (omit for mock mode)")
    ap.add_argument("--api-key", help="API key (azn_live_/azn_test_)")
    ap.add_argument("--agent", default="procurement-agent-v2")
    ap.add_argument("--count", type=int, default=len(WORKLOAD), help="number of transactions")
    ap.add_argument("--shadow", action="store_true", help="observe-only: never block, just log")
    args = ap.parse_args()

    live = bool(args.base_url and args.api_key)
    if live:
        client = Client(api_key=args.api_key, base_url=args.base_url, on_unavailable=OnUnavailable.FAIL_CLOSED)
        client.fetch_public_keys()
        mode = "LIVE"
    else:
        plane = MockPlane()
        client = Client(api_key="azn_test_demo", public_keys=plane.jwks, transport=plane)
        mode = "MOCK"

    print(f"\n  Demo agent '{args.agent}' - {mode} mode, {'shadow (observe-only)' if args.shadow else 'enforce'}\n")
    tally = {"APPROVE": 0, "DENY": 0, "REVIEW": 0, "blocked": 0}

    for i in range(args.count):
        t = WORKLOAD[i % len(WORKLOAD)]
        req = to_request(args.agent, t, i)
        decision = client.shadow(req) if args.shadow else client.authorize(req)
        tally[decision.verdict.value] = tally.get(decision.verdict.value, 0) + 1
        icon = {"APPROVE": "APPROVE", "DENY": "DENY  ", "REVIEW": "REVIEW"}[decision.verdict.value]
        print(f"  [{icon}] {t.amount:>8} USD -> {t.vendor:<16} {t.note}")
        print(f"           {decision.explanation.summary}")

        if args.shadow:
            continue  # observe-only: never enforce
        try:
            decision.enforce()  # raises unless enforceable APPROVE
            charge(req)
        except DecisionDeniedError:
            tally["blocked"] += 1
            print("      -> payment BLOCKED (not approved)")

    # Prove a decision is independently verifiable against the published key.
    sample = client.authorize(to_request(args.agent, WORKLOAD[0], 999)) if not args.shadow else None
    if sample is not None:
        verified = client.verify_decision(sample)
        print(f"\n  signature check: decision {verified.decision_id[:14]} verified={verified.signature_verified}")

    print(f"\n  summary: {tally['APPROVE']} approved, {tally['DENY']} denied, "
          f"{tally['REVIEW']} review, {tally['blocked']} payments blocked\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Runnable, offline quickstart.

The 3-line integration is the block marked below: construct a client, authorize +
enforce before the real payment, then charge. Everything else here is scaffolding so
the example runs with no server (a local Ed25519 signer + a fake transport stand in
for the decision plane).

Run:  python examples/quickstart.py
"""
from __future__ import annotations

import os
import sys

# Run from a source checkout without installing: put src/ on the path.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from trust_infra import Client
from trust_infra.transport import Response

# --- scaffolding: fake a signed APPROVE from the decision plane ------------- #
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trust_infra import canonical

_priv = Ed25519PrivateKey.generate()
_raw_pub = _priv.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
JWKS = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "demo", "x": canonical.b64url_encode(_raw_pub), "use": "sig", "status": "active"}]}


def _signed_approve() -> dict:
    decision = {
        "decision_id": "01HXYZ8K3M9QF0R7S2T4V6W8XA",
        "verdict": "APPROVE",
        "policy_version_hash": "polv_demo",
        "explanation": {"summary": "All rules satisfied.", "matched_rules": []},
        "obligations": [],
        "evaluated_at": "2026-08-27T10:32:11Z",
    }
    decision["signature"] = {
        "algorithm": "Ed25519",
        "key_id": "demo",
        "value": canonical.b64url_encode(_priv.sign(canonical.decision_signing_bytes(decision))),
        "canonicalization": "ti-decision-canon/1",
    }
    return decision


class _DemoTransport:
    def send(self, method, url, headers, body, timeout):
        return Response(200, {}, json.dumps(_signed_approve()).encode())


def charge(txn):  # your existing payment-provider call
    print(f"  charged {txn['amount']} {txn['currency']} to {txn['target']['id']}")


txn = {
    "agent_id": "procurement-agent-v2",
    "action": "payment.create",
    "amount": "1200.00",
    "currency": "USD",
    "target": {"type": "vendor", "id": "acme-supplies"},
    "idempotency_key": "idem_01HXYZ8K3M9QF0R7S2T4V6W8XA",
}

# --- the 3-line integration ------------------------------------------------- #
client = Client(api_key="azn_test_demo", public_keys=JWKS, transport=_DemoTransport())
client.authorize(txn).enforce()   # verifies the Ed25519 signature; raises unless APPROVE
charge(txn)                       # reached only on an enforceable APPROVE
# ---------------------------------------------------------------------------- #

print("done.")

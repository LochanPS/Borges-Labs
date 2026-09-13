import hashlib

import pytest

from trust_infra import canonical


def test_request_signing_string_layout():
    body = b'{"a":1}'
    out = canonical.request_signing_string("post", "/v1/authorize", "1693132331", "nonce-123", body)
    lines = out.decode("utf-8").split("\n")
    assert lines[0] == "azn-hmac/1"
    assert lines[1] == "POST"  # method uppercased
    assert lines[2] == "/v1/authorize"
    assert lines[3] == "1693132331"
    assert lines[4] == "nonce-123"
    assert lines[5] == hashlib.sha256(body).hexdigest()


def test_jcs_sorts_keys_and_is_compact():
    assert canonical.jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_jcs_rejects_floats():
    # Money is always a string; a float in signed bytes means the input is wrong.
    with pytest.raises(ValueError):
        canonical.jcs({"amount": 1200.00})


def test_decision_signing_excludes_unsigned_fields_and_normalizes_shadow():
    decision = {
        "decision_id": "d1",
        "verdict": "APPROVE",
        "policy_version_hash": "polv_x",
        "explanation": {"summary": "ok", "matched_rules": []},
        "obligations": [],
        "evaluated_at": "2026-08-27T10:32:11Z",
        # excluded from the signature:
        "latency_ms": 7,
        "record_hash": "rh_1",
        "signature_verified": True,
        "signature": {"algorithm": "Ed25519", "key_id": "k", "value": "v", "canonicalization": "ti-decision-canon/1"},
    }
    msg = canonical.decision_signing_bytes(decision).decode("utf-8")
    assert "latency_ms" not in msg
    assert "record_hash" not in msg
    assert "signature_verified" not in msg
    assert '"signature"' not in msg
    # shadow absent -> included as false
    assert '"shadow":false' in msg


def test_b64url_roundtrip_without_padding():
    raw = bytes(range(32))
    enc = canonical.b64url_encode(raw)
    assert "=" not in enc
    assert canonical.b64url_decode(enc) == raw

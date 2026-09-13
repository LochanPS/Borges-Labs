import hashlib
import hmac

import pytest

from trust_infra import (
    Client,
    ConflictError,
    DecisionDeniedError,
    RateLimitedError,
    ValidationError,
)
from trust_infra import canonical
from trust_infra.models import HoldStateName, Verdict

from _helpers import (
    FakeTransport,
    json_response,
    jwks_for,
    make_keypair,
    sample_decision,
    sample_txn,
    sign_decision,
)


def _signed_client(script, key_id="k1"):
    priv, pub = make_keypair()
    transport = FakeTransport(script)
    client = Client(api_key="azn_test_abc", public_keys=jwks_for(pub, key_id), transport=transport)
    return client, transport, priv


def test_authorize_verifies_and_returns_decision():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision("APPROVE"), priv, "k1")
    transport = FakeTransport([json_response(200, signed)])
    client = Client(api_key="azn_test_abc", public_keys=jwks_for(pub, "k1"), transport=transport)

    d = client.authorize(sample_txn())
    assert d.verdict == Verdict.APPROVE
    assert d.signature_verified is True
    assert d.approved is True
    d.enforce()  # does not raise


def test_authorize_sends_correct_hmac_headers():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    transport = FakeTransport([json_response(200, signed)])
    client = Client(
        api_key="azn_test_secret",
        public_keys=jwks_for(pub, "k1"),
        transport=transport,
        nonce_factory=lambda: "fixed-nonce-123",
        clock=lambda: 1693132331.9,  # truncated to 1693132331
    )
    client.authorize(sample_txn())

    call = transport.calls[0]
    h = call["headers"]
    assert h["X-Api-Key"] == "azn_test_secret"
    assert h["X-Nonce"] == "fixed-nonce-123"
    assert h["X-Timestamp"] == "1693132331"
    assert h["Idempotency-Key"] == sample_txn()["idempotency_key"]

    expected_sig = hmac.new(
        b"azn_test_secret",
        canonical.request_signing_string("POST", "/v1/authorize", "1693132331", "fixed-nonce-123", call["body"]),
        hashlib.sha256,
    ).hexdigest()
    assert h["X-Signature"] == expected_sig


def test_deny_decision_enforce_raises():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision("DENY"), priv, "k1")
    transport = FakeTransport([json_response(200, signed)])
    client = Client(api_key="azn_test_abc", public_keys=jwks_for(pub, "k1"), transport=transport)
    d = client.authorize(sample_txn())
    assert d.verdict == Verdict.DENY
    with pytest.raises(DecisionDeniedError):
        d.enforce()


def test_shadow_decision_never_enforced():
    priv, pub = make_keypair()
    dec = sample_decision("DENY")
    dec["shadow"] = True
    signed = sign_decision(dec, priv, "k1")
    transport = FakeTransport([json_response(200, signed)])
    client = Client(api_key="azn_test_abc", public_keys=jwks_for(pub, "k1"), transport=transport)

    d = client.shadow(sample_txn())
    assert d.shadow is True
    assert d.approved is False  # advisory is never enforceable
    d.enforce()  # must NOT raise even though verdict is DENY (observe-only)


def test_capture_parses_hold_state():
    transport = FakeTransport(
        [json_response(200, {"decision_id": "01HXYZ...", "state": "captured"})]
    )
    client = Client(api_key="azn_test_abc", public_keys={"keys": []}, transport=transport)
    hold = client.capture("01HXYZ8K3M9QF0R7S2T4V6W8XA")
    assert hold.state == HoldStateName.CAPTURED
    assert transport.calls[0]["url"].endswith("/v1/authorize/01HXYZ8K3M9QF0R7S2T4V6W8XA/capture")


def test_void_parses_hold_state():
    transport = FakeTransport([json_response(200, {"decision_id": "d", "state": "voided"})])
    client = Client(api_key="azn_test_abc", public_keys={"keys": []}, transport=transport)
    assert client.void("d").state == HoldStateName.VOIDED


def test_rate_limited_maps_to_typed_error_with_retry_after():
    problem = {"type": "t", "title": "Too Many", "status": 429, "code": "rate_limited"}
    transport = FakeTransport([json_response(429, problem, headers={"retry-after": "30"})])
    client = Client(api_key="azn_test_abc", public_keys={"keys": []}, transport=transport)
    with pytest.raises(RateLimitedError) as ei:
        client.authorize(sample_txn())
    assert ei.value.retry_after == 30
    assert ei.value.code == "rate_limited"


def test_validation_error_carries_field_pointers():
    problem = {
        "type": "t",
        "title": "Invalid",
        "status": 400,
        "code": "validation_failed",
        "errors": [{"pointer": "/amount", "detail": "must match pattern"}],
    }
    transport = FakeTransport([json_response(400, problem)])
    client = Client(api_key="azn_test_abc", public_keys={"keys": []}, transport=transport)
    with pytest.raises(ValidationError) as ei:
        client.authorize(sample_txn())
    assert ei.value.errors[0]["pointer"] == "/amount"


def test_capture_conflict_maps_to_conflict_error():
    problem = {"type": "t", "title": "Conflict", "status": 409, "code": "conflict"}
    transport = FakeTransport([json_response(409, problem)])
    client = Client(api_key="azn_test_abc", public_keys={"keys": []}, transport=transport)
    with pytest.raises(ConflictError):
        client.capture("d")


def test_bad_signature_on_authorize_raises_not_returns():
    from trust_infra import SignatureVerificationError

    priv, pub = make_keypair()
    signed = sign_decision(sample_decision("APPROVE"), priv, "k1")
    signed["verdict"] = "DENY"  # tamper after signing
    transport = FakeTransport([json_response(200, signed)])
    client = Client(api_key="azn_test_abc", public_keys=jwks_for(pub, "k1"), transport=transport)
    with pytest.raises(SignatureVerificationError):
        client.authorize(sample_txn())

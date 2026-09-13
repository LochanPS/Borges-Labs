import pytest

from trust_infra import Decision, SignatureVerificationError, verify_decision
from trust_infra.models import Verdict

from _helpers import jwks_for, make_keypair, sample_decision, sign_decision


def test_verify_real_signed_decision():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "azn-sign-2026-08")
    jwks = jwks_for(pub, "azn-sign-2026-08")

    decision = verify_decision(signed, jwks)

    assert isinstance(decision, Decision)
    assert decision.verdict == Verdict.APPROVE
    assert decision.signature_verified is True


def test_tampered_field_fails_verification():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "azn-sign-2026-08")
    jwks = jwks_for(pub, "azn-sign-2026-08")

    signed["verdict"] = "DENY"  # flip a signed field, keep the old signature

    with pytest.raises(SignatureVerificationError):
        verify_decision(signed, jwks)


def test_tampered_nested_detail_fails():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    signed["explanation"]["matched_rules"][0]["detail"] = "amount=9999.00"
    with pytest.raises(SignatureVerificationError):
        verify_decision(signed, jwks_for(pub, "k1"))


def test_unknown_key_id_fails():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    with pytest.raises(SignatureVerificationError):
        verify_decision(signed, jwks_for(pub, "different-kid"))


def test_revoked_key_never_verifies():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    with pytest.raises(SignatureVerificationError):
        verify_decision(signed, jwks_for(pub, "k1", status="revoked"))


def test_non_ed25519_algorithm_rejected():
    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    signed["signature"]["algorithm"] = "HS256"  # HMAC forbidden as a decision signature
    with pytest.raises(SignatureVerificationError):
        verify_decision(signed, jwks_for(pub, "k1"))


def test_missing_signature_rejected():
    with pytest.raises(SignatureVerificationError):
        verify_decision(sample_decision(), {"keys": []})


def test_accepts_keymap_form():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    priv, pub = make_keypair()
    signed = sign_decision(sample_decision(), priv, "k1")
    keymap = {"k1": Ed25519PublicKey.from_public_bytes(pub)}
    assert verify_decision(signed, keymap).signature_verified is True

"""Ed25519 decision-signature verification against the published public key(s).

This is the audit-receipt check: it proves a Decision was produced by the service
and not tampered with, using only the PUBLISHED public key -- no shared secret
(decision-canonicalization.md §3). HMAC is deliberately never accepted here, since a
key-holder could forge decisions with it (ROADMAP A#1).
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64url_decode, decision_signing_bytes
from .config import DECISION_CANON
from .exceptions import SignatureVerificationError
from .models import Decision

# A JWKS document: {"keys": [ {kty,crv,kid,x,use,status}, ... ]}, or a bare list of
# those JWK dicts, or a pre-parsed mapping of key_id -> Ed25519PublicKey.
PublicKeys = Union[Mapping[str, Any], List[Dict[str, Any]]]


def _load_jwks(public_keys: PublicKeys) -> Dict[str, Ed25519PublicKey]:
    """Normalize accepted public-key forms to {key_id: Ed25519PublicKey}."""
    # Already-parsed mapping of key_id -> public key object.
    if isinstance(public_keys, Mapping) and "keys" not in public_keys:
        parsed: Dict[str, Ed25519PublicKey] = {}
        for kid, val in public_keys.items():
            parsed[kid] = val if isinstance(val, Ed25519PublicKey) else _jwk_to_key(val)
        return parsed

    keys_list = public_keys["keys"] if isinstance(public_keys, Mapping) else public_keys
    out: Dict[str, Ed25519PublicKey] = {}
    for jwk in keys_list:
        if jwk.get("status") == "revoked":
            continue  # a revoked key must never validate a signature
        out[jwk["kid"]] = _jwk_to_key(jwk)
    return out


def _jwk_to_key(jwk: Dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise SignatureVerificationError(
            f"unsupported public key type kty={jwk.get('kty')} crv={jwk.get('crv')}; expected OKP/Ed25519"
        )
    raw = b64url_decode(jwk["x"])
    if len(raw) != 32:
        raise SignatureVerificationError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_decision(decision: Union[Decision, Dict[str, Any]], public_keys: PublicKeys) -> Decision:
    """Verify a Decision's Ed25519 signature. Return the Decision on success.

    Raises :class:`SignatureVerificationError` if the signature is missing, uses an
    unexpected algorithm/canonicalization, names an unknown/revoked key, or does not
    validate over the canonical bytes. On success the returned Decision has
    ``signature_verified = True``.
    """
    dec_dict = decision.to_dict() if isinstance(decision, Decision) else dict(decision)
    model = decision if isinstance(decision, Decision) else Decision.from_dict(dec_dict)

    sig = dec_dict.get("signature")
    if not sig:
        raise SignatureVerificationError("decision has no signature to verify")
    if sig.get("algorithm") != "Ed25519":
        raise SignatureVerificationError(f"unexpected signature algorithm {sig.get('algorithm')!r}")
    if sig.get("canonicalization") != DECISION_CANON:
        raise SignatureVerificationError(
            f"unexpected canonicalization {sig.get('canonicalization')!r}; SDK implements {DECISION_CANON}"
        )

    key_id = sig.get("key_id")
    keys = _load_jwks(public_keys)
    pub = keys.get(key_id)
    if pub is None:
        raise SignatureVerificationError(
            f"no published public key for key_id={key_id!r} (rotation: fetch GET /v1/keys/public)"
        )

    message = decision_signing_bytes(dec_dict)
    try:
        pub.verify(b64url_decode(sig["value"]), message)
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            f"Ed25519 signature did not verify for decision {dec_dict.get('decision_id')!r}"
        ) from exc

    model.signature_verified = True
    return model

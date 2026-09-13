"""Canonicalization primitives for both signatures in the system.

Two distinct, non-interchangeable schemes (ROADMAP A#1):

* :func:`request_signing_string` + :func:`sha256_hex` -- the ``azn-hmac/1`` canonical
  string the caller HMAC-signs (docs/request-authentication.md).
* :func:`decision_signing_bytes` -- the ``ti-decision-canon/1`` JCS bytes the server
  Ed25519-signs and any third party verifies (docs/decision-canonicalization.md).
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict

from .config import DECISION_CANON, HMAC_SCHEME

# Allowlist of Decision fields covered by the Ed25519 signature, in no particular
# order -- JCS sorts them. Mirrors decision-canonicalization.md §1 exactly.
_DECISION_SIGNED_FIELDS = (
    "decision_id",
    "verdict",
    "policy_version_hash",
    "explanation",
    "obligations",
    "evaluated_at",
    "shadow",
)


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256, used for the body digest in the HMAC string."""
    return hashlib.sha256(data).hexdigest()


def request_signing_string(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    """Build the newline-delimited ``azn-hmac/1`` canonical string (UTF-8 bytes).

    Layout (docs/request-authentication.md)::

        azn-hmac/1
        <HTTP-METHOD, uppercase>
        <request path>
        <X-Timestamp>
        <X-Nonce>
        <hex sha256(request body)>
    """
    lines = [
        HMAC_SCHEME,
        method.upper(),
        path,
        timestamp,
        nonce,
        sha256_hex(body),
    ]
    return "\n".join(lines).encode("utf-8")


def jcs(value: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme, restricted to the value shapes that
    appear in a signed Decision (strings, booleans, integers, arrays, objects, null).

    Object keys are sorted by code point (equivalent to RFC 8785's UTF-16 ordering
    for the BMP identifiers used in this contract) and emitted with no insignificant
    whitespace. Every monetary value in the contract is a decimal *string*, never a
    JSON number, so JCS number formatting never touches money -- this is the stated
    reason the contract models amounts as strings (decision-canonicalization.md §2).

    Floats are rejected rather than silently mis-serialized: no signed field is a
    float, so encountering one means the input is wrong.
    """
    _reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _reject_floats(value: Any) -> None:
    """Recursively reject floats anywhere in a to-be-signed structure. No signed
    field is a float (money is a decimal string), so a float means malformed input."""
    if isinstance(value, float):
        raise ValueError("JCS for signed decisions does not accept floats; money is a string")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def decision_signing_bytes(decision: Dict[str, Any]) -> bytes:
    """Reduce a Decision (dict form) to the exact ``ti-decision-canon/1`` message bytes.

    Takes only the allowlisted fields, normalizes ``shadow`` to a boolean
    (absent -> False), and JCS-serializes. Any excluded field (``latency_ms``,
    ``signature``, ``record_hash``, ``signature_verified``) is ignored.
    """
    signed: Dict[str, Any] = {}
    for field in _DECISION_SIGNED_FIELDS:
        if field == "shadow":
            signed["shadow"] = bool(decision.get("shadow", False))
        elif field in decision:
            signed[field] = decision[field]
    return jcs(signed)


def b64url_decode(value: str) -> bytes:
    """Decode base64url, tolerating missing padding (JWK ``x`` and signature ``value``)."""
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def b64url_encode(data: bytes) -> str:
    """Encode base64url without padding (the form the signature ``value`` uses)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

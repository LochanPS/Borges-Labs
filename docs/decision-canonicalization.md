# Decision Signature Canonicalization — `ti-decision-canon/1`

This document defines exactly which bytes are signed when the authorization service
produces a `Decision`, so that **any third party** (customer, auditor, regulator) can
reproduce the signed input and verify the Ed25519 signature independently, with no
shared secret. It is the normative reference named by
`Decision.signature.canonicalization` (`common.schema.json#/$defs/Signature`).

> Two signatures, kept distinct (ROADMAP A#1):
> - **Request auth** (caller → us) uses **HMAC** (symmetric) over the HTTP request —
>   a *separate* concern, defined by the API's request-signing headers, not here.
> - **The Decision receipt** (us → everyone) uses **Ed25519** (asymmetric) and is what
>   this document canonicalizes. HMAC here would let a key-holder forge our decisions.

## 1. Signed field set (allowlist)

The signature covers **only** these fields of the Decision, and no others:

| Field | Why signed |
|---|---|
| `decision_id` | Identity of the receipt. |
| `verdict` | The core claim (APPROVE/DENY/REVIEW). |
| `policy_version_hash` | Pins the exact policy that produced it. |
| `explanation` | The reasoning (`summary` + full `matched_rules`). |
| `obligations` | Conditions the caller must honor. |
| `evaluated_at` | The replayable evaluation instant. |
| `shadow` | Enforceability flag — signed so tampering can't flip shadow → enforceable. When absent it is treated as `false` and included as `false`. |

**Excluded from the signature (on purpose):**

- `latency_ms` — server timing, non-semantic and non-deterministic across replays.
- `signature` — you cannot sign the signature.
- `record_hash`, `signature_verified` — record-only fields added by the audit/read
  path *after* signing; they are not part of the receipt's claim.

## 2. Canonical bytes

1. Build a JSON object containing **exactly** the allowlisted fields above (with
   `shadow` normalized to a boolean).
2. Serialize with **RFC 8785 JSON Canonicalization Scheme (JCS)**: object keys sorted
   lexicographically by UTF-16 code unit, no insignificant whitespace, UTF-8 output,
   strings in canonical form. Because every monetary value in this contract is already
   a decimal **string** (never a JSON number), JCS number formatting never touches
   money — this is a deliberate reason the contract models amounts as strings.
3. The UTF-8 bytes of that JCS output are the **message**.

## 3. Sign / verify

- **Sign:** `signature.value = base64url_nopad( Ed25519_sign(privkey[key_id], message) )`,
  with `signature.algorithm = "Ed25519"`, `signature.key_id` naming the key, and
  `signature.canonicalization = "ti-decision-canon/1"`.
- **Verify:**
  1. Read `signature.key_id`; fetch the matching public key from `GET /v1/keys/public`
     (JWKS-style; `kid == key_id`, `kty == "OKP"`, `crv == "Ed25519"`).
  2. Rebuild the canonical message from the Decision per §1–§2.
  3. `Ed25519_verify(pubkey, message, base64url_decode(signature.value))`.

Mutating **any** signed field (including reordering `matched_rules` or changing one
digit of a `detail`/`evidence` value) changes the canonical bytes and fails
verification. This is exercised by the tamper test in ROADMAP Task 1.5/1.6.

## 4. Key rotation

`signature.key_id` is mandatory precisely so old decisions stay verifiable after
rotation: the public-key endpoint keeps `retiring` keys published until every
decision signed under them has aged out of retention. Never reuse a `key_id`.

## 5. Versioning

This scheme is `ti-decision-canon/1`. Any change to the signed field set or the
serialization rules requires a new identifier (`/2`, …); verifiers select behavior by
the `canonicalization` value on each Decision, so old receipts keep verifying.

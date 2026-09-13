/**
 * Ed25519 decision-signature verification against the published public key(s).
 *
 * Proves a Decision came from the service and was not tampered with, using only the
 * PUBLISHED key -- no shared secret (decision-canonicalization.md §3). HMAC is never
 * accepted here: a key-holder could forge decisions with it (ROADMAP A#1). Uses
 * node:crypto, so there is no third-party crypto dependency.
 */
import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";
import { b64urlDecode, decisionSigningBytes } from "./canonical.js";
import { DECISION_CANON } from "./config.js";
import { SignatureVerificationError } from "./errors.js";
import { DecisionResult, type Decision, type Jwk, type Jwks } from "./models.js";

/** Accepted public-key inputs: a JWKS doc, a bare JWK list, or parsed kid->KeyObject. */
export type PublicKeys = Jwks | Jwk[] | Record<string, KeyObject>;

function isKeyObject(v: unknown): v is KeyObject {
  return typeof v === "object" && v !== null && (v as KeyObject).type === "public";
}

function loadKeys(publicKeys: PublicKeys): Map<string, KeyObject> {
  const out = new Map<string, KeyObject>();

  let list: Jwk[];
  if (Array.isArray(publicKeys)) {
    list = publicKeys;
  } else if (Array.isArray((publicKeys as Jwks).keys)) {
    list = (publicKeys as Jwks).keys;
  } else {
    // Parsed mapping of kid -> KeyObject (or JWK).
    for (const [kid, val] of Object.entries(publicKeys as Record<string, KeyObject>)) {
      out.set(kid, isKeyObject(val) ? val : jwkToKey(val as unknown as Jwk));
    }
    return out;
  }

  for (const jwk of list) {
    if (jwk.status === "revoked") continue; // a revoked key must never validate
    out.set(jwk.kid, jwkToKey(jwk));
  }
  return out;
}

function jwkToKey(jwk: Jwk): KeyObject {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new SignatureVerificationError(
      `unsupported public key kty=${jwk.kty} crv=${jwk.crv}; expected OKP/Ed25519`,
    );
  }
  const raw = b64urlDecode(jwk.x);
  if (raw.length !== 32) {
    throw new SignatureVerificationError("Ed25519 public key must be 32 bytes");
  }
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
}

/**
 * Verify a Decision's Ed25519 signature. Returns a {@link DecisionResult} with
 * `signatureVerified = true` on success; throws {@link SignatureVerificationError}
 * if the signature is missing, uses an unexpected algorithm/canonicalization, names
 * an unknown/revoked key, or does not validate over the canonical bytes.
 */
export function verifyDecision(
  decision: Decision | DecisionResult | Record<string, unknown>,
  publicKeys: PublicKeys,
): DecisionResult {
  const wire: Record<string, unknown> =
    decision instanceof DecisionResult ? decision.toWire() : (decision as Record<string, unknown>);

  const sig = wire.signature as
    | { algorithm?: string; key_id?: string; value?: string; canonicalization?: string }
    | undefined;
  if (!sig) throw new SignatureVerificationError("decision has no signature to verify");
  if (sig.algorithm !== "Ed25519") {
    throw new SignatureVerificationError(`unexpected signature algorithm ${String(sig.algorithm)}`);
  }
  if (sig.canonicalization !== DECISION_CANON) {
    throw new SignatureVerificationError(
      `unexpected canonicalization ${String(sig.canonicalization)}; SDK implements ${DECISION_CANON}`,
    );
  }

  const keys = loadKeys(publicKeys);
  const pub = sig.key_id ? keys.get(sig.key_id) : undefined;
  if (!pub) {
    throw new SignatureVerificationError(
      `no published public key for key_id=${String(sig.key_id)} (fetch GET /v1/keys/public)`,
    );
  }

  const message = decisionSigningBytes(wire);
  const ok = cryptoVerify(null, message, pub, b64urlDecode(sig.value ?? ""));
  if (!ok) {
    throw new SignatureVerificationError(
      `Ed25519 signature did not verify for decision ${String(wire.decision_id)}`,
    );
  }

  const result = decision instanceof DecisionResult ? decision : DecisionResult.fromWire(wire as unknown as Decision);
  result.signatureVerified = true;
  return result;
}

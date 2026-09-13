/**
 * Client-side Ed25519 verification of a decision receipt against the published public
 * key — the in-browser "Verify signature" the auditor persona uses (Task 5.1). No
 * secret, no server round trip: it reproduces the canonical bytes and checks the
 * signature with @noble/ed25519 (WebCrypto Ed25519 support is still uneven across
 * browsers, so a small audited library is the reliable choice).
 */
import { verifyAsync } from "@noble/ed25519";
import { b64urlToBytes, decisionSigningBytes } from "./canonical";
import type { Decision, Jwk, Jwks } from "./contracts";

export type VerifyOutcome =
  | { ok: true; keyId: string }
  | { ok: false; reason: string };

function keysFrom(jwks: Jwks | Jwk[]): Jwk[] {
  return Array.isArray(jwks) ? jwks : jwks.keys;
}

/** Verify one decision against a JWKS. Pure client-side; returns a structured result
 *  rather than throwing, so the UI can render success/failure inline. */
export async function verifyDecision(
  decision: Decision | Record<string, unknown>,
  jwks: Jwks | Jwk[],
): Promise<VerifyOutcome> {
  const sig = (decision as Record<string, unknown>).signature as
    | { algorithm?: string; key_id?: string; value?: string; canonicalization?: string }
    | undefined;

  if (!sig) return { ok: false, reason: "Decision has no signature." };
  if (sig.algorithm !== "Ed25519") {
    return { ok: false, reason: `Unexpected algorithm ${sig.algorithm ?? "?"} (expected Ed25519).` };
  }
  if (sig.canonicalization !== "ti-decision-canon/1") {
    return { ok: false, reason: `Unexpected canonicalization ${sig.canonicalization ?? "?"}.` };
  }

  const jwk = keysFrom(jwks).find((k) => k.kid === sig.key_id);
  if (!jwk) return { ok: false, reason: `No published key for key_id ${sig.key_id ?? "?"}.` };
  if (jwk.status === "revoked") return { ok: false, reason: `Signing key ${jwk.kid} is revoked.` };
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    return { ok: false, reason: "Published key is not an Ed25519 OKP key." };
  }

  try {
    const pub = b64urlToBytes(jwk.x);
    const signature = b64urlToBytes(sig.value ?? "");
    const message = decisionSigningBytes(decision as Record<string, unknown>);
    const ok = await verifyAsync(signature, message, pub);
    return ok
      ? { ok: true, keyId: jwk.kid }
      : { ok: false, reason: "Signature does not match the canonical decision bytes." };
  } catch (e) {
    return { ok: false, reason: `Verification error: ${(e as Error).message}` };
  }
}

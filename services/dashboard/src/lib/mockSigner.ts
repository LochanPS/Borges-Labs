/** Server-only: sign the mock decisions with a real per-process Ed25519 key and expose
 *  the matching JWKS, so the in-browser Verify button genuinely validates even in mock
 *  mode (no backend required). */
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { decisionSigningBytes } from "./canonical";
import type { Decision, Jwks } from "./contracts";

const KEY_ID = "azn-sign-2026-08";
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };

export const mockJwks: Jwks = {
  keys: [{ kty: jwk.kty, crv: jwk.crv, kid: KEY_ID, x: jwk.x, use: "sig", status: "active" }],
};

/** Return a copy of the decision with a real Ed25519 signature over its canonical bytes. */
export function signMockDecision(decision: Decision): Decision {
  const value = Buffer.from(
    edSign(null, decisionSigningBytes(decision as unknown as Record<string, unknown>), privateKey),
  ).toString("base64url");
  return { ...decision, signature: { algorithm: "Ed25519", key_id: KEY_ID, value, canonicalization: "ti-decision-canon/1" } };
}

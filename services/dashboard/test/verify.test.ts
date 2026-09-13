import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { decisionSigningBytes } from "../src/lib/canonical";
import { verifyDecision } from "../src/lib/verify";

function makeKeyAndDecision(verdict = "APPROVE") {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  const decision: Record<string, unknown> = {
    decision_id: "01HXYZ8K3M9QF0R7S2T4V6W8XA",
    verdict,
    policy_version_hash: "polv_demo",
    explanation: { summary: "ok", matched_rules: [] },
    obligations: [],
    latency_ms: 7,
    evaluated_at: "2026-08-27T10:32:11Z",
  };
  const value = Buffer.from(edSign(null, decisionSigningBytes(decision), privateKey)).toString("base64url");
  decision.signature = { algorithm: "Ed25519", key_id: "k1", value, canonicalization: "ti-decision-canon/1" };
  const jwks = { keys: [{ kty: jwk.kty, crv: jwk.crv, kid: "k1", x: jwk.x, use: "sig", status: "active" as const }] };
  return { decision, jwks };
}

test("verifies a real signed decision client-side", async () => {
  const { decision, jwks } = makeKeyAndDecision();
  const r = await verifyDecision(decision, jwks);
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.keyId, "k1");
});

test("rejects a tampered verdict", async () => {
  const { decision, jwks } = makeKeyAndDecision();
  const tampered = { ...decision, verdict: "DENY" };
  const r = await verifyDecision(tampered, jwks);
  assert.equal(r.ok, false);
});

test("rejects unknown key id", async () => {
  const { decision } = makeKeyAndDecision();
  const other = makeKeyAndDecision();
  const r = await verifyDecision(decision, other.jwks);
  assert.equal(r.ok, false);
});

test("rejects a revoked key", async () => {
  const { decision, jwks } = makeKeyAndDecision();
  jwks.keys[0].status = "revoked";
  const r = await verifyDecision(decision, jwks);
  assert.equal(r.ok, false);
});

test("rejects non-Ed25519 algorithm", async () => {
  const { decision, jwks } = makeKeyAndDecision();
  (decision.signature as Record<string, unknown>).algorithm = "HS256";
  const r = await verifyDecision(decision, jwks);
  assert.equal(r.ok, false);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyDecision, SignatureVerificationError, DecisionResult } from "../src/index.js";
import { makeKeypair, sampleDecision, signDecision } from "./helpers.js";

test("verifies a real signed decision", () => {
  const { privateKey, jwks } = makeKeypair("azn-sign-2026-08");
  const signed = signDecision(sampleDecision(), privateKey, "azn-sign-2026-08");
  const decision = verifyDecision(signed, jwks);
  assert.ok(decision instanceof DecisionResult);
  assert.equal(decision.verdict, "APPROVE");
  assert.equal(decision.signatureVerified, true);
});

test("tampered top-level field fails", () => {
  const { privateKey, jwks } = makeKeypair();
  const signed = signDecision(sampleDecision(), privateKey);
  signed.verdict = "DENY";
  assert.throws(() => verifyDecision(signed, jwks), SignatureVerificationError);
});

test("tampered nested detail fails", () => {
  const { privateKey, jwks } = makeKeypair();
  const signed = signDecision(sampleDecision(), privateKey) as any;
  signed.explanation.matched_rules[0].detail = "amount=9999.00";
  assert.throws(() => verifyDecision(signed, jwks), SignatureVerificationError);
});

test("unknown key id fails", () => {
  const { privateKey } = makeKeypair("k1");
  const other = makeKeypair("different-kid");
  const signed = signDecision(sampleDecision(), privateKey, "k1");
  assert.throws(() => verifyDecision(signed, other.jwks), SignatureVerificationError);
});

test("revoked key never verifies", () => {
  const { privateKey, jwks } = makeKeypair("k1", "revoked");
  const signed = signDecision(sampleDecision(), privateKey, "k1");
  assert.throws(() => verifyDecision(signed, jwks), SignatureVerificationError);
});

test("non-Ed25519 algorithm rejected", () => {
  const { privateKey, jwks } = makeKeypair();
  const signed = signDecision(sampleDecision(), privateKey) as any;
  signed.signature.algorithm = "HS256";
  assert.throws(() => verifyDecision(signed, jwks), SignatureVerificationError);
});

test("missing signature rejected", () => {
  assert.throws(() => verifyDecision(sampleDecision(), { keys: [] }), SignatureVerificationError);
});

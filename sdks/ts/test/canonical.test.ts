import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonical } from "../src/index.js";

test("request signing string layout", () => {
  const body = Buffer.from('{"a":1}');
  const out = canonical
    .requestSigningString("post", "/v1/authorize", "1693132331", "nonce-123", body)
    .toString("utf8");
  const lines = out.split("\n");
  assert.equal(lines[0], "azn-hmac/1");
  assert.equal(lines[1], "POST");
  assert.equal(lines[2], "/v1/authorize");
  assert.equal(lines[3], "1693132331");
  assert.equal(lines[4], "nonce-123");
  assert.equal(lines[5], createHash("sha256").update(body).digest("hex"));
});

test("jcs sorts keys and is compact", () => {
  assert.equal(canonical.jcs({ b: 1, a: 2 }), '{"a":2,"b":1}');
});

test("jcs rejects non-integer numbers", () => {
  assert.throws(() => canonical.jcs({ amount: 1200.5 }), /money is a string/);
});

test("decision signing excludes unsigned fields and normalizes shadow", () => {
  const decision = {
    decision_id: "d1",
    verdict: "APPROVE",
    policy_version_hash: "polv_x",
    explanation: { summary: "ok", matched_rules: [] },
    obligations: [],
    evaluated_at: "2026-08-27T10:32:11Z",
    latency_ms: 7,
    record_hash: "rh_1",
    signature_verified: true,
    signature: { algorithm: "Ed25519", key_id: "k", value: "v", canonicalization: "ti-decision-canon/1" },
  };
  const msg = canonical.decisionSigningBytes(decision).toString("utf8");
  assert.ok(!msg.includes("latency_ms"));
  assert.ok(!msg.includes("record_hash"));
  assert.ok(!msg.includes("signature_verified"));
  assert.ok(!msg.includes('"signature"'));
  assert.ok(msg.includes('"shadow":false'));
});

test("base64url round trip without padding", () => {
  const raw = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const enc = canonical.b64urlEncode(raw);
  assert.ok(!enc.includes("="));
  assert.deepEqual(canonical.b64urlDecode(enc), raw);
});

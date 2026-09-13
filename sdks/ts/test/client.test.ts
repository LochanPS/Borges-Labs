import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  Client,
  ConflictError,
  DecisionDeniedError,
  RateLimitedError,
  SignatureVerificationError,
  ValidationError,
  canonical,
  logger,
} from "../src/index.js";
import {
  FakeTransport,
  jsonResponse,
  makeKeypair,
  sampleDecision,
  sampleTxn,
  signDecision,
} from "./helpers.js";

logger.sink = { info: () => {}, warn: () => {} };

test("authorize verifies and returns decision", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const signed = signDecision(sampleDecision("APPROVE"), privateKey, "k1");
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: jwks, transport: new FakeTransport([jsonResponse(200, signed)]) });
  const d = await client.authorize(sampleTxn());
  assert.equal(d.verdict, "APPROVE");
  assert.equal(d.signatureVerified, true);
  assert.equal(d.approved, true);
  d.enforce();
});

test("authorize sends correct HMAC headers", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const signed = signDecision(sampleDecision(), privateKey, "k1");
  const transport = new FakeTransport([jsonResponse(200, signed)]);
  const client = new Client({
    apiKey: "azn_test_secret",
    publicKeys: jwks,
    transport,
    nonceFactory: () => "fixed-nonce-123",
    clock: () => 1693132331900, // -> 1693132331 seconds
  });
  await client.authorize(sampleTxn());

  const call = transport.calls[0]!;
  assert.equal(call.headers["X-Api-Key"], "azn_test_secret");
  assert.equal(call.headers["X-Nonce"], "fixed-nonce-123");
  assert.equal(call.headers["X-Timestamp"], "1693132331");
  assert.equal(call.headers["Idempotency-Key"], sampleTxn().idempotency_key);

  const expected = createHmac("sha256", "azn_test_secret")
    .update(canonical.requestSigningString("POST", "/v1/authorize", "1693132331", "fixed-nonce-123", call.body!))
    .digest("hex");
  assert.equal(call.headers["X-Signature"], expected);
});

test("DENY decision enforce throws", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const signed = signDecision(sampleDecision("DENY"), privateKey, "k1");
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: jwks, transport: new FakeTransport([jsonResponse(200, signed)]) });
  const d = await client.authorize(sampleTxn());
  assert.equal(d.verdict, "DENY");
  assert.throws(() => d.enforce(), DecisionDeniedError);
});

test("shadow decision never enforced", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const dec = sampleDecision("DENY");
  dec.shadow = true;
  const signed = signDecision(dec, privateKey, "k1");
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: jwks, transport: new FakeTransport([jsonResponse(200, signed)]) });
  const d = await client.shadow(sampleTxn());
  assert.equal(d.shadow, true);
  assert.equal(d.approved, false);
  d.enforce(); // must not throw even though verdict is DENY
});

test("capture parses hold state", async () => {
  const transport = new FakeTransport([jsonResponse(200, { decision_id: "01HXYZ", state: "captured" })]);
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: { keys: [] }, transport });
  const hold = await client.capture("01HXYZ8K3M9QF0R7S2T4V6W8XA");
  assert.equal(hold.state, "captured");
  assert.ok(transport.calls[0]!.url.endsWith("/v1/authorize/01HXYZ8K3M9QF0R7S2T4V6W8XA/capture"));
});

test("void parses hold state", async () => {
  const transport = new FakeTransport([jsonResponse(200, { decision_id: "d", state: "voided" })]);
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: { keys: [] }, transport });
  assert.equal((await client.void("d")).state, "voided");
});

test("rate limited maps to typed error with retryAfter", async () => {
  const problem = { type: "t", title: "Too Many", status: 429, code: "rate_limited" };
  const transport = new FakeTransport([jsonResponse(429, problem, { "retry-after": "30" })]);
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: { keys: [] }, transport });
  await assert.rejects(client.authorize(sampleTxn()), (e: unknown) => {
    assert.ok(e instanceof RateLimitedError);
    assert.equal(e.retryAfter, 30);
    assert.equal(e.code, "rate_limited");
    return true;
  });
});

test("validation error carries field pointers", async () => {
  const problem = {
    type: "t",
    title: "Invalid",
    status: 400,
    code: "validation_failed",
    errors: [{ pointer: "/amount", detail: "must match pattern" }],
  };
  const transport = new FakeTransport([jsonResponse(400, problem)]);
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: { keys: [] }, transport });
  await assert.rejects(client.authorize(sampleTxn()), (e: unknown) => {
    assert.ok(e instanceof ValidationError);
    assert.equal(e.errors[0]!.pointer, "/amount");
    return true;
  });
});

test("capture conflict maps to ConflictError", async () => {
  const problem = { type: "t", title: "Conflict", status: 409, code: "conflict" };
  const transport = new FakeTransport([jsonResponse(409, problem)]);
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: { keys: [] }, transport });
  await assert.rejects(client.capture("d"), ConflictError);
});

test("bad signature on authorize throws, not returns", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const signed = signDecision(sampleDecision("APPROVE"), privateKey, "k1") as any;
  signed.verdict = "DENY"; // tamper after signing
  const client = new Client({ apiKey: "azn_test_abc", publicKeys: jwks, transport: new FakeTransport([jsonResponse(200, signed)]) });
  await assert.rejects(client.authorize(sampleTxn()), SignatureVerificationError);
});

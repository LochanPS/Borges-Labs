import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Client,
  OnUnavailable,
  DecisionDeniedError,
  logger,
} from "../src/index.js";
import {
  FakeTransport,
  TransportError,
  jsonResponse,
  makeKeypair,
  sampleDecision,
  sampleTxn,
  signDecision,
} from "./helpers.js";

// Silence fail-mode warnings during tests.
logger.sink = { info: () => {}, warn: () => {} };

function client(mode: OnUnavailable, script: Array<any>) {
  return new Client({
    apiKey: "azn_test_abc",
    publicKeys: { keys: [] },
    onUnavailable: mode,
    transport: new FakeTransport(script),
  });
}

test("FAIL_CLOSED on network error denies", async () => {
  const c = client(OnUnavailable.FailClosed, [new TransportError("connection refused")]);
  const d = await c.authorize(sampleTxn());
  assert.equal(d.verdict, "DENY");
  assert.equal(d.degraded, true);
  assert.equal(d.signature, undefined);
  assert.throws(() => d.enforce(), DecisionDeniedError);
});

test("FAIL_CLOSED on 503 denies", async () => {
  const problem = { type: "about:blank", title: "Unavailable", status: 503, code: "unavailable" };
  const c = client(OnUnavailable.FailClosed, [jsonResponse(503, problem)]);
  const d = await c.authorize(sampleTxn());
  assert.equal(d.verdict, "DENY");
  assert.equal(d.degraded, true);
});

test("FAIL_OPEN approves but marks degraded and unsigned", async () => {
  const c = client(OnUnavailable.FailOpen, [new TransportError("timeout")]);
  const d = await c.authorize(sampleTxn());
  assert.equal(d.verdict, "APPROVE");
  assert.equal(d.degraded, true);
  assert.equal(d.signature, undefined);
  assert.equal(d.signatureVerified, false);
  d.enforce(); // explicit opt-in: does not throw
});

test("LOCAL_CACHE hit replays prior decision", async () => {
  const { privateKey, jwks } = makeKeypair("k1");
  const signed = signDecision(sampleDecision("APPROVE"), privateKey, "k1");
  const transport = new FakeTransport([jsonResponse(200, signed), new TransportError("down")]);
  const c = new Client({
    apiKey: "azn_test_abc",
    publicKeys: jwks,
    onUnavailable: OnUnavailable.LocalCache,
    transport,
  });

  const first = await c.authorize(sampleTxn());
  assert.equal(first.verdict, "APPROVE");
  assert.equal(first.signatureVerified, true);

  const second = await c.authorize(sampleTxn()); // same idempotency_key, plane down
  assert.equal(second.verdict, "APPROVE");
  assert.equal(second.servedFromCache, true);
  assert.equal(second.degraded, true);
});

test("LOCAL_CACHE miss fails closed", async () => {
  const c = client(OnUnavailable.LocalCache, [new TransportError("down")]);
  const d = await c.authorize(sampleTxn());
  assert.equal(d.verdict, "DENY");
  assert.equal(d.degraded, true);
});

for (const mode of [OnUnavailable.FailClosed, OnUnavailable.LocalCache]) {
  test(`${mode} never silently approves`, async () => {
    const c = client(mode, [new TransportError("down")]);
    const d = await c.authorize(sampleTxn());
    assert.notEqual(d.verdict, "APPROVE");
  });
}

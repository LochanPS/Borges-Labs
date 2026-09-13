/** Parse the committed contract examples so model/generator drift fails here. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonical, DecisionResult, type AuthorizeRequest, type Decision } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const EXAMPLES = join(here, "..", "..", "..", "contracts", "examples");
const load = (name: string) => JSON.parse(readFileSync(join(EXAMPLES, name), "utf8"));

test("authorize-request example fits the generated type", () => {
  const raw = load("authorize-request.example.json") as AuthorizeRequest;
  assert.equal(raw.agent_id, "procurement-agent-v2");
  assert.equal(raw.amount, "5000.00"); // money stays a string
  assert.equal(raw.counter_snapshot?.counters[0]?.window, "month");
});

test("decision-approve example parses and signed bytes are stable", () => {
  const raw = load("decision-approve.example.json") as Decision;
  const decision = DecisionResult.fromWire(raw);
  assert.equal(decision.verdict, "APPROVE");
  assert.equal(decision.obligations[0]?.type, "capture_within");
  assert.equal(decision.signature?.canonicalization, "ti-decision-canon/1");
  assert.deepEqual(
    canonical.decisionSigningBytes(raw as unknown as Record<string, unknown>),
    canonical.decisionSigningBytes(decision.toWire()),
  );
});

test("decision-deny example parses", () => {
  const raw = load("decision-deny.example.json") as Decision;
  assert.equal(DecisionResult.fromWire(raw).verdict, "DENY");
});

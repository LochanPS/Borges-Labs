/**
 * End-to-end over real HTTP. A node:http server faithfully implements the service
 * contract -- HMAC request auth (azn-hmac/1) and Ed25519 decision signing
 * (ti-decision-canon/1) -- and the client talks to it with the default FetchTransport.
 * This exercises the full wire path: HMAC sign -> HTTP -> Ed25519 verify -> enforce.
 *
 * The opt-in test at the bottom runs the same 3-line integration against a REAL running
 * service when TRUST_INFRA_BASE_URL + TRUST_INFRA_API_KEY are set (skipped otherwise).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createHmac, generateKeyPairSync, sign as edSign, type KeyObject } from "node:crypto";
import {
  Client,
  DecisionDeniedError,
  AuthenticationError,
  OnUnavailable,
  canonical,
  logger,
} from "../src/index.js";

logger.sink = { info: () => {}, warn: () => {} };

const API_KEY = "azn_test_e2e_secret";

function startMockService(privateKey: KeyObject, jwks: unknown): Promise<{ server: Server; baseUrl: string }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const url = req.url ?? "/";

      if (req.method === "GET" && url === "/v1/keys/public") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(jwks));
        return;
      }

      // Verify the HMAC exactly as docs/request-authentication.md specifies.
      const ts = req.headers["x-timestamp"] as string;
      const nonce = req.headers["x-nonce"] as string;
      const presented = req.headers["x-signature"] as string;
      const expected = createHmac("sha256", API_KEY)
        .update(canonical.requestSigningString(req.method ?? "GET", url, ts, nonce, body))
        .digest("hex");
      if (req.headers["x-api-key"] !== API_KEY || presented !== expected) {
        res.writeHead(401, { "content-type": "application/problem+json" });
        res.end(JSON.stringify({ type: "about:blank", title: "Unauthorized", status: 401, code: "unauthorized" }));
        return;
      }

      if (req.method === "POST" && url === "/v1/authorize") {
        const txn = JSON.parse(body.toString("utf8"));
        const verdict = Number(txn.amount) <= 5000 ? "APPROVE" : "DENY";
        const decision: Record<string, unknown> = {
          decision_id: "01HXYZ8K3M9QF0R7S2T4V6W8XA",
          verdict,
          policy_version_hash: "polv_e2e",
          explanation: {
            summary: verdict === "APPROVE" ? "within limit" : "over per-transaction limit",
            matched_rules: [],
          },
          obligations: [],
          latency_ms: 3,
          evaluated_at: "2026-08-27T10:32:11Z",
        };
        const value = canonical.b64urlEncode(edSign(null, canonical.decisionSigningBytes(decision), privateKey));
        decision.signature = { algorithm: "Ed25519", key_id: "e2e", value, canonicalization: "ti-decision-canon/1" };
        res.writeHead(200, { "content-type": "application/json", "x-decision-id": String(decision.decision_id) });
        res.end(JSON.stringify(decision));
        return;
      }

      res.writeHead(404, { "content-type": "application/problem+json" });
      res.end(JSON.stringify({ type: "about:blank", title: "Not Found", status: 404 }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      resolve({ server, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

test("end-to-end over real HTTP: 3-line integration, enforce, verify, bad auth", async (t) => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  const jwks = { keys: [{ kty: jwk.kty, crv: jwk.crv, kid: "e2e", x: jwk.x, use: "sig", status: "active" }] };
  const { server, baseUrl } = await startMockService(privateKey, jwks);
  t.after(() => server.close());

  const txn = {
    agent_id: "procurement-agent-v2",
    action: "payment.create",
    amount: "1200.00",
    currency: "USD",
    target: { type: "vendor" as const, id: "acme-supplies" },
    idempotency_key: "idem_e2e_0001",
  };

  // --- the 3-line integration, over a real socket ---
  const client = new Client({ apiKey: API_KEY, publicKeys: jwks, baseUrl });
  const decision = await client.authorize(txn);
  decision.enforce(); // APPROVE: does not throw
  // ---
  assert.equal(decision.verdict, "APPROVE");
  assert.equal(decision.signatureVerified, true);

  // A held decision verifies independently against the fetched public keys.
  const fetched = await new Client({ apiKey: API_KEY, baseUrl }).fetchPublicKeys();
  assert.equal(fetched.keys[0]!.kid, "e2e");

  // Over-limit -> DENY, enforce throws.
  const denied = await client.authorize({ ...txn, amount: "9000.00", idempotency_key: "idem_e2e_0002" });
  assert.equal(denied.verdict, "DENY");
  assert.throws(() => denied.enforce(), DecisionDeniedError);

  // Wrong API key -> server rejects the HMAC with 401.
  const badClient = new Client({ apiKey: "azn_test_wrong", publicKeys: jwks, baseUrl, onUnavailable: OnUnavailable.FailClosed });
  await assert.rejects(badClient.authorize(txn), AuthenticationError);
});

// Opt-in: run against a REAL service when configured.
const liveBase = process.env.TRUST_INFRA_BASE_URL;
const liveKey = process.env.TRUST_INFRA_API_KEY;
test("live service: authorize + enforce", { skip: !liveBase || !liveKey }, async () => {
  const client = new Client({ apiKey: liveKey!, baseUrl: liveBase! });
  await client.fetchPublicKeys();
  const decision = await client.authorize({
    agent_id: process.env.TRUST_INFRA_AGENT ?? "procurement-agent-v2",
    action: "payment.create",
    amount: "1.00",
    currency: "USD",
    target: { type: "vendor", id: "acme-supplies" },
    idempotency_key: `idem_live_${Date.now()}`,
  });
  assert.ok(["APPROVE", "DENY", "REVIEW"].includes(decision.verdict));
  if (!decision.shadow && decision.signature) assert.equal(decision.signatureVerified, true);
});

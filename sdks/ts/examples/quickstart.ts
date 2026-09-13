/**
 * Runnable, offline quickstart.  Run:  npm run example
 *
 * The 3-line integration is the marked block. The rest is scaffolding so it runs with
 * no server: a local Ed25519 signer + an in-memory transport stand in for the plane.
 */
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { Client, canonical } from "../src/index.js";
import type { HttpResponse, Transport } from "../src/transport.js";

// --- scaffolding: fake a signed APPROVE from the decision plane ---
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
const jwks = { keys: [{ kty: jwk.kty, crv: jwk.crv, kid: "demo", x: jwk.x, use: "sig", status: "active" as const }] };

const signedApprove = () => {
  const decision: Record<string, unknown> = {
    decision_id: "01HXYZ8K3M9QF0R7S2T4V6W8XA",
    verdict: "APPROVE",
    policy_version_hash: "polv_demo",
    explanation: { summary: "All rules satisfied.", matched_rules: [] },
    obligations: [],
    evaluated_at: "2026-08-27T10:32:11Z",
  };
  decision.signature = {
    algorithm: "Ed25519",
    key_id: "demo",
    value: canonical.b64urlEncode(edSign(null, canonical.decisionSigningBytes(decision), privateKey)),
    canonicalization: "ti-decision-canon/1",
  };
  return decision;
};

const demoTransport: Transport = {
  async send(): Promise<HttpResponse> {
    return { status: 200, headers: {}, body: Buffer.from(JSON.stringify(signedApprove())) };
  },
};

async function charge(txn: { amount: string; currency: string; target: { id: string } }) {
  console.log(`  charged ${txn.amount} ${txn.currency} to ${txn.target.id}`);
}

const txn = {
  agent_id: "procurement-agent-v2",
  action: "payment.create",
  amount: "1200.00",
  currency: "USD",
  target: { type: "vendor" as const, id: "acme-supplies" },
  idempotency_key: "idem_01HXYZ8K3M9QF0R7S2T4V6W8XA",
};

// --- the 3-line integration ---
const client = new Client({ apiKey: "azn_test_demo", publicKeys: jwks, transport: demoTransport });
(await client.authorize(txn)).enforce(); // verifies the Ed25519 signature; throws unless APPROVE
await charge(txn); // reached only on an enforceable APPROVE
// ---

console.log("done.");

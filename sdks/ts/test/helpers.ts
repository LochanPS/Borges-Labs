import {
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { canonical } from "../src/index.js";
import type { HttpResponse, Transport } from "../src/transport.js";
import { TransportError } from "../src/errors.js";

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  jwks: { keys: Array<Record<string, unknown>> };
}

export function makeKeypair(kid = "k1", status = "active"): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  return {
    privateKey,
    publicKey,
    jwks: { keys: [{ kty: jwk.kty, crv: jwk.crv, kid, x: jwk.x, use: "sig", status }] },
  };
}

export function signDecision(
  decision: Record<string, unknown>,
  privateKey: KeyObject,
  keyId = "k1",
): Record<string, unknown> {
  const message = canonical.decisionSigningBytes(decision);
  const value = canonical.b64urlEncode(cryptoSign(null, message, privateKey));
  return {
    ...decision,
    signature: { algorithm: "Ed25519", key_id: keyId, value, canonicalization: "ti-decision-canon/1" },
  };
}

export function sampleDecision(verdict = "APPROVE"): Record<string, unknown> {
  return {
    decision_id: "01HXYZ8K3M9QF0R7S2T4V6W8XA",
    verdict,
    policy_version_hash: "polv_9f2a1c7e4b5d6a8f0c1e2d3b4a5f6e7d",
    explanation: {
      summary: "All rules satisfied.",
      matched_rules: [
        {
          rule_id: "per_txn_5k",
          type: "per_transaction_limit",
          result: "SATISFIED",
          detail: "amount=1200.00 <= per_transaction_limit=5000.00 USD",
          evidence: { amount: "1200.00", limit: "5000.00", currency: "USD" },
        },
      ],
    },
    obligations: [],
    latency_ms: 7,
    evaluated_at: "2026-08-27T10:32:11Z",
  };
}

export function sampleTxn() {
  return {
    agent_id: "procurement-agent-v2",
    action: "payment.create",
    amount: "1200.00",
    currency: "USD",
    target: { type: "vendor" as const, id: "acme-supplies" },
    jurisdiction: "US",
    idempotency_key: "idem_01HXYZ8K3M9QF0R7S2T4V6W8XA",
  };
}

export function jsonResponse(
  status: number,
  payload: unknown,
  headers: Record<string, string> = {},
): HttpResponse {
  return { status, headers, body: Buffer.from(JSON.stringify(payload), "utf8") };
}

type ScriptItem = HttpResponse | Error;

/** Scripted transport: each queued item is a Response to return or an Error to throw. */
export class FakeTransport implements Transport {
  script: ScriptItem[];
  calls: Array<{ method: string; url: string; headers: Record<string, string>; body?: Uint8Array }> = [];

  constructor(script: ScriptItem[] = []) {
    this.script = [...script];
  }

  async send(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: Uint8Array | undefined,
    _timeoutMs: number,
  ): Promise<HttpResponse> {
    this.calls.push({ method, url, headers, body });
    const item = this.script.shift();
    if (item === undefined) throw new Error(`FakeTransport unscripted call: ${method} ${url}`);
    if (item instanceof Error) throw item;
    return item;
  }
}

export { TransportError };

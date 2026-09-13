/**
 * Isomorphic canonicalization (browser + server, no Node APIs) for the decision
 * signature scheme `ti-decision-canon/1` (docs/decision-canonicalization.md). Shared by
 * the client-side Verify button and the server-side signed API client.
 */

const DECISION_SIGNED_FIELDS = [
  "decision_id",
  "verdict",
  "policy_version_hash",
  "explanation",
  "obligations",
  "evaluated_at",
  "shadow",
] as const;

/** RFC 8785 JSON Canonicalization Scheme, restricted to the value shapes in a signed
 *  Decision (string, boolean, integer, array, object, null). Rejects non-integer
 *  numbers — money is always a decimal string. */
export function jcs(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("JCS for signed decisions does not accept non-integer numbers");
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(obj[k])}`).join(",")}}`;
  }
  throw new Error(`JCS cannot serialize value of type ${t}`);
}

/** The exact `ti-decision-canon/1` message bytes for a Decision: allowlisted fields
 *  only, `shadow` normalized to a boolean, JCS-encoded to UTF-8. */
export function decisionSigningBytes(decision: Record<string, unknown>): Uint8Array {
  const signed: Record<string, unknown> = {};
  for (const field of DECISION_SIGNED_FIELDS) {
    if (field === "shadow") signed.shadow = Boolean(decision.shadow ?? false);
    else if (field in decision) signed[field] = decision[field];
  }
  return new TextEncoder().encode(jcs(signed));
}

/** Decode base64url (padding optional) to bytes. Works in browser and Node. */
export function b64urlToBytes(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  if (typeof atob === "function") {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}

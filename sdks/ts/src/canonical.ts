/**
 * Canonicalization primitives for both signatures in the system (ROADMAP A#1):
 *
 * - {@link requestSigningString} + {@link sha256Hex} build the `azn-hmac/1` string
 *   the caller HMAC-signs (docs/request-authentication.md).
 * - {@link decisionSigningBytes} builds the `ti-decision-canon/1` JCS bytes the
 *   server Ed25519-signs and any third party verifies (docs/decision-canonicalization.md).
 */
import { createHash } from "node:crypto";
import { HMAC_SCHEME } from "./config.js";

/** Fields covered by the Ed25519 decision signature (decision-canonicalization.md §1). */
const DECISION_SIGNED_FIELDS = [
  "decision_id",
  "verdict",
  "policy_version_hash",
  "explanation",
  "obligations",
  "evaluated_at",
  "shadow",
] as const;

/** Lowercase hex SHA-256. */
export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * The newline-delimited `azn-hmac/1` canonical string (UTF-8 bytes):
 *
 * ```
 * azn-hmac/1
 * <HTTP-METHOD, uppercase>
 * <request path>
 * <X-Timestamp>
 * <X-Nonce>
 * <hex sha256(request body)>
 * ```
 */
export function requestSigningString(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array | string,
): Buffer {
  const lines = [HMAC_SCHEME, method.toUpperCase(), path, timestamp, nonce, sha256Hex(body)];
  return Buffer.from(lines.join("\n"), "utf8");
}

/**
 * RFC 8785 JSON Canonicalization Scheme, restricted to the value shapes that appear
 * in a signed Decision (string, boolean, integer, array, object, null). Object keys
 * are sorted by UTF-16 code unit (JS string order == JCS order for this contract) and
 * emitted with no insignificant whitespace. Money is always a decimal string, so JCS
 * number formatting never touches it. Floats are rejected: no signed field is a float.
 */
export function jcs(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string") return JSON.stringify(value);
  if (t === "boolean") return value ? "true" : "false";
  if (t === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("JCS for signed decisions does not accept non-integer numbers; money is a string");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(jcs).join(",")}]`;
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(obj[k])}`).join(",")}}`;
  }
  throw new Error(`JCS cannot serialize value of type ${t}`);
}

/**
 * Reduce a Decision to the exact `ti-decision-canon/1` message bytes: only the
 * allowlisted fields, `shadow` normalized to a boolean (absent -> false), JCS-encoded.
 * Excluded fields (`latency_ms`, `signature`, `record_hash`, `signature_verified`)
 * are ignored.
 */
export function decisionSigningBytes(decision: Record<string, unknown>): Buffer {
  const signed: Record<string, unknown> = {};
  for (const field of DECISION_SIGNED_FIELDS) {
    if (field === "shadow") {
      signed.shadow = Boolean(decision.shadow ?? false);
    } else if (field in decision) {
      signed[field] = decision[field];
    }
  }
  return Buffer.from(jcs(signed), "utf8");
}

/** Decode base64url (padding optional). */
export function b64urlDecode(value: string): Buffer {
  return Buffer.from(value, "base64url");
}

/** Encode base64url without padding. */
export function b64urlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

/** Server-only HMAC request signing (azn-hmac/1). Uses node:crypto; never import into
 *  client components. */
import { createHash, createHmac, randomUUID } from "node:crypto";

const HMAC_SCHEME = "azn-hmac/1";

function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Build the azn-hmac/1 headers for a control-plane request. */
export function signedHeaders(
  apiKey: string,
  method: string,
  path: string,
  body: Uint8Array,
): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomUUID();
  const signingString = [
    HMAC_SCHEME,
    method.toUpperCase(),
    path,
    timestamp,
    nonce,
    sha256Hex(body),
  ].join("\n");
  const signature = createHmac("sha256", apiKey).update(signingString).digest("hex");
  return {
    "X-Api-Key": apiKey,
    Authorization: `Bearer ${apiKey}`,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "X-Signature": signature,
  };
}

/**
 * HTTP transport abstraction. The default uses the global `fetch` (Node >=18), so the
 * SDK has no runtime dependencies. Inject a custom transport (undici, a proxy, or a
 * fake) for tests or special environments.
 */
import { TransportError } from "./errors.js";

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface Transport {
  /**
   * Perform one HTTP round trip. MUST throw {@link TransportError} for any network
   * failure/timeout (no HTTP status exists). A normal 4xx/5xx MUST be returned as an
   * {@link HttpResponse} so the client can parse the RFC 7807 body.
   */
  send(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: Uint8Array | undefined,
    timeoutMs: number,
  ): Promise<HttpResponse>;
}

/** Default transport built on global fetch with an AbortController timeout. */
export class FetchTransport implements Transport {
  async send(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: Uint8Array | undefined,
    timeoutMs: number,
  ): Promise<HttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, {
        method: method.toUpperCase(),
        headers,
        body: body && body.length ? body : undefined,
        signal: controller.signal,
      });
      const buf = new Uint8Array(await resp.arrayBuffer());
      const h: Record<string, string> = {};
      resp.headers.forEach((v, k) => {
        h[k.toLowerCase()] = v;
      });
      return { status: resp.status, headers: h, body: buf };
    } catch (err) {
      // fetch rejects only on network error / abort -- never on an HTTP error status.
      throw new TransportError(`request to ${url} failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }
}

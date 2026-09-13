/** Server-side configuration derived from environment. Never import into client code
 *  anything that reads AUTHZ_API_KEY — it must stay server-only. */

export const config = {
  /** Control-plane base URL (authorize-svc). Empty => mock mode. */
  baseUrl: process.env.AUTHZ_BASE_URL?.replace(/\/+$/, "") ?? "",
  /** Admin API key used to sign control-plane requests (server-only). */
  apiKey: process.env.AUTHZ_API_KEY ?? "",
  requestTimeoutMs: Number(process.env.AUTHZ_TIMEOUT_MS ?? 5000),
};

/** True when both a base URL and an API key are configured; otherwise the app serves
 *  seeded mock data so every screen renders without a running backend. */
export function liveBackend(): boolean {
  return Boolean(config.baseUrl && config.apiKey);
}

/** True when Clerk keys are present; otherwise the app runs in dev-bypass mode. */
export function clerkEnabled(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY && process.env.CLERK_SECRET_KEY,
  );
}

/** Client configuration: fail-mode policy and protocol constants. */

/**
 * What the SDK does when the decision plane cannot be reached or returns 503.
 *
 * The plane deliberately never guesses, so the caller must state its risk posture.
 * The one thing the SDK NEVER does is turn an upstream failure into a silent
 * APPROVE (TRD §10): FAIL_OPEN approvals are explicit, marked `degraded`, unsigned,
 * and logged.
 */
export enum OnUnavailable {
  /** Treat an unreachable plane as DENY. Safe default for the payment path. */
  FailClosed = "FAIL_CLOSED",
  /** Treat an unreachable plane as APPROVE. Explicit, loud, opt-in only. */
  FailOpen = "FAIL_OPEN",
  /** Replay the last decision cached for this idempotency_key; miss -> FAIL_CLOSED. */
  LocalCache = "LOCAL_CACHE",
}

/** HMAC request-signing scheme label (docs/request-authentication.md). */
export const HMAC_SCHEME = "azn-hmac/1";
/** Ed25519 decision-signature canonicalization label (docs/decision-canonicalization.md). */
export const DECISION_CANON = "ti-decision-canon/1";
/** Default max clock skew the server tolerates on X-Timestamp (AUTHZ_HMAC_MAX_SKEW). */
export const DEFAULT_MAX_SKEW_SECONDS = 300;

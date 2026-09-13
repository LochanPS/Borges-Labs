/**
 * @trust-infra/sdk -- TypeScript/Node SDK for the AI Transaction Authorization
 * Infrastructure /v1 API.
 *
 * ```ts
 * import { Client } from "@trust-infra/sdk";
 *
 * const client = new Client({ apiKey: "azn_live_...", publicKeys: jwks });
 * (await client.authorize(txn)).enforce();  // throws unless APPROVE; shadow never blocks
 * await charge(txn);                          // your payment call, reached only on APPROVE
 * ```
 *
 * Two signatures, kept distinct (ROADMAP A#1): requests are HMAC-signed (symmetric);
 * decisions are Ed25519-signed (asymmetric) and verified here against the published
 * public key with no shared secret.
 */
export { Client, type ClientOptions } from "./client.js";
export { OnUnavailable, HMAC_SCHEME, DECISION_CANON, DEFAULT_MAX_SKEW_SECONDS } from "./config.js";
export { verifyDecision, type PublicKeys } from "./verify.js";
export { FetchTransport, type Transport, type HttpResponse } from "./transport.js";
export { logger, type LogSink } from "./logger.js";
export * as canonical from "./canonical.js";

export {
  DecisionResult,
  Verdict,
  type VerdictValue,
  type DecisionInput,
  type DecisionAnnotations,
  type HoldState,
  type HoldStateName,
  type Jwk,
  type Jwks,
  // generated wire types
  type AuthorizeRequest,
  type Decision,
  type Explanation,
  type Obligation,
  type Signature,
  type Target,
  type Counter,
  type CounterSnapshot,
  type MatchedRule,
  type PredicateResult,
  type MonetaryAmount,
  type CurrencyCode,
  type Jurisdiction,
  type Timestamp,
  type ULID,
  type Problem,
} from "./models.js";

export {
  TrustInfraError,
  ProblemError,
  ValidationError,
  AuthenticationError,
  ReplayError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  RateLimitedError,
  ServiceUnavailableError,
  TransportError,
  SignatureVerificationError,
  DecisionDeniedError,
  type ProblemFieldError,
} from "./errors.js";

/**
 * SDK models: the generated wire types plus a {@link DecisionResult} wrapper that
 * carries enforcement helpers and SDK-local annotations (how the decision was
 * obtained). Wire shapes come from the contract; nothing here re-declares them.
 */
import type {
  Decision,
  MatchedRule,
  Obligation,
  Signature,
} from "./contracts/generated.js";
import { DecisionDeniedError } from "./errors.js";
import { logger } from "./logger.js";

export type {
  AuthorizeRequest,
  Decision,
  Obligation,
  Signature,
  Target,
  Counter,
  CounterSnapshot,
  MatchedRule,
  PredicateResult,
  MonetaryAmount,
  CurrencyCode,
  Jurisdiction,
  Timestamp,
  ULID,
  Problem,
} from "./contracts/generated.js";

/** The `explanation` object of a Decision (inline in the schema; named here for reuse). */
export interface Explanation {
  summary: string;
  matched_rules: MatchedRule[];
}

/** Verdict values (the schema models this inline; exported here for runtime use). */
export const Verdict = {
  Approve: "APPROVE",
  Deny: "DENY",
  Review: "REVIEW",
} as const;
export type VerdictValue = (typeof Verdict)[keyof typeof Verdict];

/** Budget-hold lifecycle state (OpenAPI components/schemas/HoldState). */
export type HoldStateName = "held" | "captured" | "voided" | "expired";

export interface HoldState {
  decision_id: string;
  state: HoldStateName;
  budget_id?: string;
  amount?: string;
  currency?: string;
  expires_at?: string;
}

/** A published Ed25519 verification key (GET /v1/keys/public, JWKS-style). */
export interface Jwk {
  kty: string;
  crv: string;
  kid: string;
  x: string;
  use?: string;
  status?: "active" | "retiring" | "revoked";
}

export interface Jwks {
  keys: Jwk[];
}

export interface DecisionAnnotations {
  /** True once the Ed25519 signature has been validated; null when unverified. */
  signatureVerified?: boolean | null;
  /** True for a locally synthesized fail-mode decision (not from the plane). */
  degraded?: boolean;
  /** True when replayed from the LOCAL_CACHE store. */
  servedFromCache?: boolean;
}

/**
 * A Decision plus how the SDK obtained it, with enforcement helpers.
 *
 * A `degraded` result is a client-side fail-mode fallback -- it has no `signature`
 * and is never a signed receipt.
 */
/** The fields accepted when constructing a result (signature/latency optional so a
 *  synthetic fail-mode decision is representable). A wire {@link Decision} satisfies it. */
export interface DecisionInput {
  decision_id: string;
  verdict: Decision["verdict"];
  policy_version_hash: string;
  explanation: Explanation;
  obligations: Obligation[];
  evaluated_at: string;
  signature?: Signature;
  latency_ms?: number;
  shadow?: boolean;
  record_hash?: string;
}

export class DecisionResult {
  decision_id: string;
  verdict: Decision["verdict"];
  policy_version_hash: string;
  explanation: Explanation;
  obligations: Obligation[];
  evaluated_at: string;
  signature?: Signature;
  latency_ms?: number;
  shadow: boolean;
  record_hash?: string;

  signatureVerified: boolean | null;
  degraded: boolean;
  servedFromCache: boolean;

  constructor(wire: DecisionInput, ann: DecisionAnnotations = {}) {
    this.decision_id = wire.decision_id;
    this.verdict = wire.verdict;
    this.policy_version_hash = wire.policy_version_hash;
    this.explanation = wire.explanation;
    this.obligations = wire.obligations;
    this.evaluated_at = wire.evaluated_at;
    this.signature = wire.signature;
    this.latency_ms = wire.latency_ms;
    this.shadow = Boolean(wire.shadow ?? false);
    this.record_hash = wire.record_hash;
    this.signatureVerified = ann.signatureVerified ?? null;
    this.degraded = ann.degraded ?? false;
    this.servedFromCache = ann.servedFromCache ?? false;
  }

  static fromWire(wire: Decision, ann: DecisionAnnotations = {}): DecisionResult {
    return new DecisionResult(wire, ann);
  }

  /** True only for an enforceable APPROVE. A shadow/advisory decision is never enforceable. */
  get approved(): boolean {
    return this.verdict === "APPROVE" && !this.shadow;
  }

  /**
   * Throw {@link DecisionDeniedError} unless the verdict is an enforceable APPROVE.
   * A shadow/advisory decision is observe-only: this logs and returns without blocking.
   * Returns `this` so it chains.
   */
  enforce(): this {
    if (this.shadow) {
      logger.sink.info(
        `shadow decision ${this.decision_id} (verdict=${this.verdict}) not enforced (advisory)`,
      );
      return this;
    }
    if (this.verdict !== "APPROVE") {
      throw new DecisionDeniedError(this);
    }
    return this;
  }

  /** Serialize back to the wire shape (e.g. to re-verify the signature). */
  toWire(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      decision_id: this.decision_id,
      verdict: this.verdict,
      policy_version_hash: this.policy_version_hash,
      explanation: this.explanation,
      obligations: this.obligations,
      evaluated_at: this.evaluated_at,
    };
    if (this.latency_ms !== undefined) out.latency_ms = this.latency_ms;
    if (this.shadow) out.shadow = true;
    if (this.record_hash !== undefined) out.record_hash = this.record_hash;
    if (this.signature !== undefined) out.signature = this.signature;
    return out;
  }
}

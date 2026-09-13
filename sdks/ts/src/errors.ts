/**
 * Typed error hierarchy.
 *
 * API errors mirror RFC 7807 Problem Details (contracts/schemas/error.schema.json):
 * the SDK parses the `application/problem+json` body into a {@link ProblemError}
 * subclass chosen by HTTP status, so callers `instanceof`-switch rather than
 * string-matching prose.
 */
import type { Problem } from "./contracts/generated.js";

export class TrustInfraError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export interface ProblemFieldError {
  pointer: string;
  detail: string;
}

/** An RFC 7807 problem response from the API. */
export class ProblemError extends TrustInfraError {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail?: string;
  readonly instance?: string;
  readonly code?: string;
  readonly errors: ProblemFieldError[];
  readonly retryAfter?: number;
  readonly raw: Partial<Problem>;

  constructor(problem: Partial<Problem>, retryAfter?: number) {
    const status = Number(problem.status ?? 0);
    const title = problem.title ?? "";
    super(`${status} ${title}${problem.detail ? `: ${problem.detail}` : ""}`.trim());
    this.type = problem.type ?? "about:blank";
    this.title = title;
    this.status = status;
    this.detail = problem.detail;
    this.instance = problem.instance;
    this.code = problem.code;
    this.errors = (problem.errors ?? []) as ProblemFieldError[];
    this.retryAfter = retryAfter;
    this.raw = problem;
  }

  /** Build the most specific ProblemError subclass for a parsed problem body. */
  static from(problem: Partial<Problem>, retryAfter?: number): ProblemError {
    const status = Number(problem.status ?? 0);
    const code = problem.code;
    const Cls = selectProblemClass(status, code);
    return new Cls(problem, retryAfter);
  }
}

export class ValidationError extends ProblemError {} // 400 / 422
export class AuthenticationError extends ProblemError {} // 401
export class ReplayError extends AuthenticationError {} // code === replay_detected
export class ForbiddenError extends ProblemError {} // 403
export class NotFoundError extends ProblemError {} // 404
export class ConflictError extends ProblemError {} // 409
export class RateLimitedError extends ProblemError {} // 429, see retryAfter
export class ServiceUnavailableError extends ProblemError {} // 503 -> triggers fail-mode

function selectProblemClass(status: number, code?: string): new (p: Partial<Problem>, r?: number) => ProblemError {
  if (code === "replay_detected") return ReplayError;
  switch (status) {
    case 400:
    case 422:
      return ValidationError;
    case 401:
      return AuthenticationError;
    case 403:
      return ForbiddenError;
    case 404:
      return NotFoundError;
    case 409:
      return ConflictError;
    case 429:
      return RateLimitedError;
    case 503:
      return ServiceUnavailableError;
    default:
      return ProblemError;
  }
}

/** Network failure/timeout reaching the plane. With a 503 this drives the fail-mode. */
export class TransportError extends TrustInfraError {}

/** Ed25519 signature on a Decision did not verify -- the decision is not trustworthy. */
export class SignatureVerificationError extends TrustInfraError {}

/** Thrown by `DecisionResult.enforce()` when the verdict is not an enforceable APPROVE. */
export class DecisionDeniedError extends TrustInfraError {
  readonly decision: unknown;
  constructor(decision: { verdict: string; explanation?: { summary?: string } }) {
    const summary = decision.explanation?.summary ?? "";
    super(`transaction not approved (verdict=${decision.verdict}): ${summary}`.trim());
    this.decision = decision;
  }
}

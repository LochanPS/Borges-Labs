/**
 * The async client: one-call authorize/shadow plus capture/void and third-party-style
 * decision verification.
 *
 * Responsibilities (TRD §10, "thin"): canonicalize + HMAC-sign each request, attach
 * nonce + timestamp, call the API, verify the Ed25519 decision signature, and apply the
 * explicit `onUnavailable` fail-mode. It NEVER turns an upstream failure into a silent
 * APPROVE.
 */
import { createHmac, randomUUID, randomBytes } from "node:crypto";
import { requestSigningString } from "./canonical.js";
import { OnUnavailable } from "./config.js";
import {
  ProblemError,
  ServiceUnavailableError,
  TransportError,
} from "./errors.js";
import { logger } from "./logger.js";
import {
  DecisionResult,
  Verdict,
  type AuthorizeRequest,
  type Decision,
  type HoldState,
  type Jwks,
} from "./models.js";
import { FetchTransport, type HttpResponse, type Transport } from "./transport.js";
import { verifyDecision, type PublicKeys } from "./verify.js";

export interface ClientOptions {
  apiKey: string;
  /** Published Ed25519 keys for verification. Auto-fetched from GET /v1/keys/public if omitted. */
  publicKeys?: PublicKeys;
  baseUrl?: string;
  onUnavailable?: OnUnavailable;
  timeoutMs?: number;
  /** Verify every signed decision before returning it (default true). */
  verifySignatures?: boolean;
  transport?: Transport;
  cache?: Map<string, DecisionResult>;
  /** Epoch milliseconds source (injectable for tests). Default Date.now. */
  clock?: () => number;
  /** Per-request nonce source (injectable for tests). Default a random UUID. */
  nonceFactory?: () => string;
}

export class Client {
  readonly apiKey: string;
  readonly baseUrl: string;
  readonly onUnavailable: OnUnavailable;
  readonly timeoutMs: number;
  readonly verifySignatures: boolean;
  private readonly transport: Transport;
  private readonly cache: Map<string, DecisionResult>;
  private readonly clock: () => number;
  private readonly nonce: () => string;
  private publicKeys?: PublicKeys;

  constructor(opts: ClientOptions) {
    if (!opts.apiKey) throw new Error("apiKey is required");
    this.apiKey = opts.apiKey;
    this.baseUrl = (opts.baseUrl ?? "https://api.trust-infra.dev").replace(/\/+$/, "");
    this.onUnavailable = opts.onUnavailable ?? OnUnavailable.FailClosed;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.verifySignatures = opts.verifySignatures ?? true;
    this.transport = opts.transport ?? new FetchTransport();
    this.cache = opts.cache ?? new Map();
    this.clock = opts.clock ?? (() => Date.now());
    this.nonce = opts.nonceFactory ?? (() => randomUUID());
    this.publicKeys = opts.publicKeys;
  }

  // --------------------------------------------------------------- //
  // Public API
  // --------------------------------------------------------------- //

  /**
   * Evaluate `txn` and return a verified, enforceable decision. Typical use:
   *
   * ```ts
   * (await client.authorize(txn)).enforce();  // throws unless APPROVE
   * await charge(txn);                          // reached only on APPROVE
   * ```
   */
  async authorize(txn: AuthorizeRequest): Promise<DecisionResult> {
    return this.authorizeInternal(txn);
  }

  /**
   * Evaluate `txn` in shadow/observe-only mode: the decision is returned and logged but
   * never enforced, removing adoption risk (PRD §9). Flip to {@link authorize} +
   * `.enforce()` when ready.
   */
  async shadow(txn: AuthorizeRequest): Promise<DecisionResult> {
    const decision = await this.authorizeInternal(txn);
    logger.sink.info(
      `shadow decision ${decision.decision_id} verdict=${decision.verdict} (advisory, not enforced)`,
    );
    return decision;
  }

  /** Commit the budget hold an APPROVE placed (two-phase, A#2). POST /v1/authorize/{id}/capture. */
  async capture(decisionId: string): Promise<HoldState> {
    return (await this.request("POST", `/v1/authorize/${encodeURIComponent(decisionId)}/capture`)) as HoldState;
  }

  /** Release the budget hold an APPROVE placed (two-phase, A#2). POST /v1/authorize/{id}/void. */
  async void(decisionId: string): Promise<HoldState> {
    return (await this.request("POST", `/v1/authorize/${encodeURIComponent(decisionId)}/void`)) as HoldState;
  }

  /**
   * Verify a Decision's Ed25519 signature against the published public key. Works for
   * any decision the caller holds (e.g. one fetched from the audit log or handed over
   * by a third party). Requires public keys to be available -- pass them to the
   * constructor or `await client.fetchPublicKeys()` first.
   */
  verifyDecision(decision: Decision | DecisionResult | Record<string, unknown>): DecisionResult {
    if (this.publicKeys === undefined) {
      throw new Error("no public keys loaded; pass publicKeys to the Client or await fetchPublicKeys() first");
    }
    return verifyDecision(decision, this.publicKeys);
  }

  /** GET /v1/keys/public (unauthenticated JWKS) and cache it on the client. */
  async fetchPublicKeys(): Promise<Jwks> {
    const resp = await this.transport.send(
      "GET",
      `${this.baseUrl}/v1/keys/public`,
      { Accept: "application/json" },
      undefined,
      this.timeoutMs,
    );
    if (resp.status !== 200) throw this.problemFromResponse(resp);
    const jwks = JSON.parse(Buffer.from(resp.body).toString("utf8")) as Jwks;
    this.publicKeys = jwks;
    return jwks;
  }

  // --------------------------------------------------------------- //
  // Authorize core + fail-mode handling
  // --------------------------------------------------------------- //

  private async authorizeInternal(txn: AuthorizeRequest): Promise<DecisionResult> {
    let data: Decision;
    try {
      data = (await this.request("POST", "/v1/authorize", txn as unknown as Record<string, unknown>)) as Decision;
    } catch (err) {
      if (err instanceof TransportError || err instanceof ServiceUnavailableError) {
        return this.handleUnavailable(txn, err);
      }
      throw err;
    }

    let decision = DecisionResult.fromWire(data);
    if (this.verifySignatures && decision.signature) {
      // A signature that does not verify is a hard failure -- never returned as trustworthy.
      decision = verifyDecision(decision, await this.ensurePublicKeys());
    }
    if (this.onUnavailable === OnUnavailable.LocalCache) {
      this.cache.set(txn.idempotency_key, decision);
    }
    return decision;
  }

  private handleUnavailable(txn: AuthorizeRequest, cause: Error): DecisionResult {
    const mode = this.onUnavailable;

    if (mode === OnUnavailable.LocalCache) {
      const cached = this.cache.get(txn.idempotency_key);
      if (cached) {
        logger.sink.warn(
          `decision plane unavailable (${cause.message}); serving cached decision ${cached.decision_id} for idempotency_key=${txn.idempotency_key}`,
        );
        return new DecisionResult(cached, {
          signatureVerified: cached.signatureVerified,
          degraded: true,
          servedFromCache: true,
        });
      }
      logger.sink.warn(
        `decision plane unavailable (${cause.message}); LOCAL_CACHE miss for idempotency_key=${txn.idempotency_key}; failing closed (DENY)`,
      );
      return this.synthetic(
        Verdict.Deny,
        `Decision plane unavailable and no cached decision for this idempotency_key; failing closed (DENY). Cause: ${cause.message}`,
      );
    }

    if (mode === OnUnavailable.FailOpen) {
      logger.sink.warn(
        `decision plane unavailable (${cause.message}); onUnavailable=FAIL_OPEN -> returning an UNSIGNED, DEGRADED synthetic APPROVE. Not auditable.`,
      );
      return this.synthetic(
        Verdict.Approve,
        `Decision plane unavailable; failing OPEN (APPROVE) per onUnavailable=FAIL_OPEN. Unsigned, degraded, not an audit receipt. Cause: ${cause.message}`,
      );
    }

    // FAIL_CLOSED (default).
    logger.sink.warn(`decision plane unavailable (${cause.message}); onUnavailable=FAIL_CLOSED -> DENY`);
    return this.synthetic(
      Verdict.Deny,
      `Decision plane unavailable; failing closed (DENY) per onUnavailable=FAIL_CLOSED. Cause: ${cause.message}`,
    );
  }

  private synthetic(verdict: Decision["verdict"], summary: string): DecisionResult {
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    return new DecisionResult(
      {
        decision_id: `local_${randomBytes(8).toString("hex")}`,
        verdict,
        policy_version_hash: "",
        explanation: { summary, matched_rules: [] },
        obligations: [],
        evaluated_at: now,
        shadow: false,
      },
      { signatureVerified: false, degraded: true },
    );
  }

  // --------------------------------------------------------------- //
  // Signed HTTP
  // --------------------------------------------------------------- //

  private async request(
    method: string,
    path: string,
    bodyObj?: Record<string, unknown>,
  ): Promise<unknown> {
    const body = bodyObj !== undefined ? Buffer.from(JSON.stringify(bodyObj), "utf8") : undefined;
    const timestamp = String(Math.floor(this.clock() / 1000)); // Unix seconds (docs/request-authentication.md)
    const nonce = this.nonce();
    const signingString = requestSigningString(method, path, timestamp, nonce, body ?? Buffer.alloc(0));
    const signature = createHmac("sha256", this.apiKey).update(signingString).digest("hex");

    const headers: Record<string, string> = {
      "X-Api-Key": this.apiKey,
      Authorization: `Bearer ${this.apiKey}`,
      "X-Timestamp": timestamp,
      "X-Nonce": nonce,
      "X-Signature": signature,
      Accept: "application/json",
    };
    if (body) headers["Content-Type"] = "application/json";
    const idem = bodyObj?.idempotency_key;
    if (typeof idem === "string") headers["Idempotency-Key"] = idem;

    const resp = await this.transport.send(method, `${this.baseUrl}${path}`, headers, body, this.timeoutMs);
    if (resp.status >= 200 && resp.status < 300) {
      return resp.body.length ? JSON.parse(Buffer.from(resp.body).toString("utf8")) : {};
    }
    throw this.problemFromResponse(resp);
  }

  private problemFromResponse(resp: HttpResponse): ProblemError {
    let problem: Record<string, unknown> = {};
    try {
      if (resp.body.length) problem = JSON.parse(Buffer.from(resp.body).toString("utf8"));
    } catch {
      problem = {};
    }
    if (problem.status === undefined) problem.status = resp.status;
    if (problem.title === undefined) problem.title = `HTTP ${resp.status}`;
    const ra = resp.headers["retry-after"];
    const retryAfter = ra && /^\d+$/.test(ra) ? Number(ra) : undefined;
    return ProblemError.from(problem, retryAfter);
  }

  private async ensurePublicKeys(): Promise<PublicKeys> {
    if (this.publicKeys === undefined) await this.fetchPublicKeys();
    return this.publicKeys as PublicKeys;
  }
}

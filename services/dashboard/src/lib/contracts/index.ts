// Contract types for the dashboard: generated wire types + control-plane view types.
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
} from "./generated";

export * from "./controlplane";

export type Verdict = "APPROVE" | "DENY" | "REVIEW";

/** JWKS document returned by GET /v1/keys/public. */
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

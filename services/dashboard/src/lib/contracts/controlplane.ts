/**
 * Control-plane view types mirroring the OpenAPI component schemas
 * (contracts/openapi.v1.yaml #/components/schemas) that the dashboard consumes but
 * which are not part of the JSON-Schema files the type generator reads.
 *
 * Keep in lockstep with the OpenAPI components. (A future generator pass can emit
 * these from the spec directly.)
 *
 * NOTE: API-key management endpoints (create/revoke) are not yet in the frozen /v1
 * contract — only GET /v1/keys/public exists. The dashboard's key screen targets the
 * intended additive paths (POST /v1/keys, POST /v1/keys/{id}/revoke) and falls back to
 * mock data until they land. See lib/api.ts.
 */
import type { MatchedRule, Timestamp } from "./generated";

export type PolicyStatus = "draft" | "published";

/** A policy rule — the shared shape from policy.schema.json#/$defs/Rule. Kept loose
 *  here (the authoritative validation happens server-side at publish). */
export interface Rule {
  rule_id: string;
  type: MatchedRule["type"];
  /** Predicate-specific parameters (e.g. { limit, currency } or { allow: [...] }). */
  params: Record<string, unknown>;
  /** Combining hint some predicates carry; optional. */
  effect?: "deny" | "review" | "require";
}

export interface Policy {
  id: string;
  org_id: string;
  name: string;
  agents: string[];
  rules: Rule[];
  status: PolicyStatus;
  active_version_hash?: string;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface PolicySignature {
  algorithm: "Ed25519";
  key_id: string;
  value: string;
  canonicalization: "ti-policy-canon/1";
}

export interface PolicyVersion {
  version_hash: string;
  policy_id: string;
  org_id: string;
  name: string;
  agents: string[];
  rules: Rule[];
  signature: PolicySignature;
  author: string;
  parent_hash?: string;
  published_at: Timestamp;
}

export interface BundleRef {
  org_id: string;
  policy_id: string;
  version_hash: string;
  updated_at: Timestamp;
}

export interface PolicyWriteRequest {
  name: string;
  agents?: string[];
  rules: Rule[];
}

export interface DecisionPage {
  data: import("./generated").Decision[];
  next_cursor: string | null;
}

export interface HealthStatus {
  status: "ok" | "degraded";
  build?: string;
  enrichment?: "ok" | "degraded" | "disabled";
}

/** API key as the dashboard shows it. The raw secret is returned ONCE on create. */
export interface ApiKey {
  id: string;
  prefix: string;
  org_id: string;
  scopes?: string[];
  is_active: boolean;
  shadow: boolean;
  created_at: Timestamp;
  last_used_at?: Timestamp;
}

export interface CreatedApiKey extends ApiKey {
  /** Full secret, shown exactly once at creation and never retrievable again. */
  secret: string;
}

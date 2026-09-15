/**
 * Server-only control-plane API client. Talks to authorize-svc with azn-hmac/1-signed
 * requests when configured; otherwise serves seeded mock data so every screen renders.
 *
 * The decision plane is never called synchronously from the payment path here — this is
 * the control plane / audit read path (TRD §3 boundary rule).
 *
 * Contract note: the frozen /v1 spec has GET /v1/policies/{id}, /active, publish,
 * rollback, versions, decisions, and keys/public — but no list-policies or key-
 * management endpoints yet. Those screens use mock/derived data and target the intended
 * additive paths; see README "Contract gaps".
 */
import { config, liveBackend } from "./config";
import { signedHeaders } from "./signing";
import {
  MOCK_ACTIVE,
  MOCK_DECISIONS,
  MOCK_KEYS,
  MOCK_POLICY,
  MOCK_VERSIONS,
} from "./mock";
import { mockJwks, signMockDecision } from "./mockSigner";
import type {
  ApiKey,
  BundleRef,
  CreatedApiKey,
  Decision,
  DecisionPage,
  HealthStatus,
  Jwks,
  Policy,
  PolicyVersion,
  Verdict,
} from "./contracts";

const signedMocks = () => MOCK_DECISIONS.map(signMockDecision);

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const bytes = body !== undefined ? new TextEncoder().encode(JSON.stringify(body)) : new Uint8Array(0);
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...signedHeaders(config.apiKey, method, path, bytes),
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.requestTimeoutMs);
  try {
    const res = await fetch(`${config.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? Buffer.from(bytes) : undefined,
      signal: controller.signal,
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}`);
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

// --- Reads ---------------------------------------------------------------- //

export async function getHealth(): Promise<HealthStatus> {
  if (!liveBackend()) return { status: "ok", build: "mock", enrichment: "disabled" };
  try {
    return await call<HealthStatus>("GET", "/v1/health");
  } catch {
    return { status: "degraded", build: "unreachable" };
  }
}

export async function getPublicKeys(): Promise<Jwks> {
  if (!liveBackend()) return mockJwks;
  try {
    return await call<Jwks>("GET", "/v1/keys/public");
  } catch {
    return mockJwks;
  }
}

export interface DecisionFilters {
  agent_id?: string;
  verdict?: Verdict;
  limit?: number;
  cursor?: string;
}

export async function listDecisions(filters: DecisionFilters = {}): Promise<DecisionPage> {
  if (!liveBackend()) {
    let data = signedMocks();
    if (filters.verdict) data = data.filter((d) => d.verdict === filters.verdict);
    return { data, next_cursor: null };
  }
  const qs = new URLSearchParams();
  if (filters.agent_id) qs.set("agent_id", filters.agent_id);
  if (filters.verdict) qs.set("verdict", filters.verdict);
  qs.set("limit", String(filters.limit ?? 50));
  if (filters.cursor) qs.set("cursor", filters.cursor);
  try {
    return await call<DecisionPage>("GET", `/v1/decisions?${qs.toString()}`);
  } catch {
    return { data: signedMocks(), next_cursor: null };
  }
}

export async function getDecision(id: string): Promise<Decision | null> {
  if (!liveBackend()) return signedMocks().find((d) => d.decision_id === id) ?? null;
  try {
    return await call<Decision>("GET", `/v1/decisions/${encodeURIComponent(id)}`);
  } catch {
    return signedMocks().find((d) => d.decision_id === id) ?? null;
  }
}

export async function getActivePolicy(): Promise<BundleRef | null> {
  if (!liveBackend()) return MOCK_ACTIVE;
  try {
    return await call<BundleRef>("GET", "/v1/policies/active");
  } catch {
    return MOCK_ACTIVE;
  }
}

export async function listPolicies(): Promise<Policy[]> {
  if (!liveBackend()) return [MOCK_POLICY];
  try {
    const res = await call<{ data: Policy[] }>("GET", "/v1/policies");
    return res.data;
  } catch {
    return [MOCK_POLICY];
  }
}

export async function getPolicy(id: string): Promise<Policy | null> {
  if (!liveBackend()) return MOCK_POLICY.id === id ? MOCK_POLICY : null;
  try {
    return await call<Policy>("GET", `/v1/policies/${encodeURIComponent(id)}`);
  } catch {
    return MOCK_POLICY.id === id ? MOCK_POLICY : null;
  }
}

export async function listPolicyVersions(id: string): Promise<PolicyVersion[]> {
  if (!liveBackend()) return MOCK_VERSIONS;
  try {
    const res = await call<{ data: PolicyVersion[] }>("GET", `/v1/policies/${encodeURIComponent(id)}/versions`);
    return res.data;
  } catch {
    return MOCK_VERSIONS;
  }
}

export async function listKeys(): Promise<ApiKey[]> {
  if (!liveBackend()) return MOCK_KEYS;
  try {
    const res = await call<{ data: ApiKey[] }>("GET", "/v1/keys");
    return res.data;
  } catch {
    return MOCK_KEYS;
  }
}

// --- Playground: fire a test authorization ------------------------------- //

export interface PlaygroundInput {
  agent_id: string;
  action: string;
  amount: string;
  currency: string;
  vendor: string;
}

/**
 * Run one authorization for the in-dashboard Playground. Live: signs + POSTs
 * /v1/authorize. Mock: applies simple rules and returns a REAL Ed25519-signed decision
 * (so the client-side Verify button genuinely validates). Returns the decision plus the
 * JWKS to verify it against.
 */
export async function authorizeTest(
  input: PlaygroundInput,
): Promise<{ decision: Decision; jwks: Jwks }> {
  const txn = {
    agent_id: input.agent_id,
    action: input.action,
    amount: input.amount,
    currency: input.currency,
    target: { type: "vendor", id: input.vendor },
    idempotency_key: `pg_${Date.now()}`,
  };

  if (liveBackend()) {
    const decision = (await call("POST", "/v1/authorize", txn)) as Decision;
    const jwks = await getPublicKeys();
    return { decision, jwks };
  }

  // Mock: rules mirror the demo agent (allowlist, 5000 per-txn, 8000 review ceiling).
  const amt = Number(input.amount);
  const allowed = new Set(["acme-supplies", "globex"]);
  let verdict: Decision["verdict"];
  let detail: string;
  let ruleType = "per_transaction_limit";
  if (!allowed.has(input.vendor)) {
    verdict = "DENY";
    ruleType = "vendor_blocklist";
    detail = `vendor '${input.vendor}' is not on the allowlist`;
  } else if (amt > 8000) {
    verdict = "DENY";
    ruleType = "rolling_budget";
    detail = `amount=${input.amount} exceeds the monthly budget`;
  } else if (amt > 5000) {
    verdict = "REVIEW";
    detail = `amount=${input.amount} > per_transaction_limit=5000.00 ${input.currency}; step-up required`;
  } else {
    verdict = "APPROVE";
    detail = `amount=${input.amount} <= per_transaction_limit=5000.00 ${input.currency}`;
  }
  const base = {
    decision_id: `01HXYZPG${Date.now().toString(36).toUpperCase()}`.slice(0, 26),
    verdict,
    policy_version_hash: "polv_playground",
    explanation: {
      summary: detail,
      matched_rules: [{ rule_id: "playground", type: ruleType, result: verdict === "APPROVE" ? "SATISFIED" : verdict, detail }],
    },
    obligations: verdict === "APPROVE" ? [{ type: "capture_within", detail: "capture after payment", params: { ttl_seconds: 120 } }] : [],
    latency_ms: 3,
    evaluated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  } as unknown as Decision;
  return { decision: signMockDecision(base), jwks: mockJwks };
}

// --- Writes (control plane) ---------------------------------------------- //

export async function createPolicy(body: import("./contracts").PolicyWriteRequest): Promise<Policy> {
  if (!liveBackend()) {
    return {
      ...MOCK_POLICY,
      id: `pol_${Date.now()}`,
      name: body.name,
      agents: body.agents ?? [],
      rules: body.rules,
      status: "draft",
      active_version_hash: undefined,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
  }
  return call<Policy>("POST", "/v1/policies", body);
}

export async function updatePolicy(id: string, body: import("./contracts").PolicyWriteRequest): Promise<Policy> {
  if (!liveBackend()) {
    return { ...MOCK_POLICY, id, name: body.name, agents: body.agents ?? [], rules: body.rules, updated_at: new Date().toISOString() };
  }
  return call<Policy>("PUT", `/v1/policies/${encodeURIComponent(id)}`, body);
}

export async function publishPolicy(id: string, author?: string): Promise<PolicyVersion> {
  if (!liveBackend()) {
    return { ...MOCK_VERSIONS[0], published_at: new Date().toISOString(), author: author ?? "you@org-demo.example" };
  }
  return call<PolicyVersion>("POST", `/v1/policies/${encodeURIComponent(id)}/publish`, author ? { author } : {});
}

export async function rollbackPolicy(id: string, versionHash: string): Promise<PolicyVersion> {
  if (!liveBackend()) {
    const v = MOCK_VERSIONS.find((x) => x.version_hash === versionHash) ?? MOCK_VERSIONS[0];
    return { ...v, published_at: new Date().toISOString() };
  }
  return call<PolicyVersion>("POST", `/v1/policies/${encodeURIComponent(id)}/rollback`, { version_hash: versionHash });
}

export async function createKey(input: { env: "live" | "test"; shadow: boolean; tier?: string }): Promise<CreatedApiKey> {
  if (!liveBackend()) {
    // Mock: mint a plausible one-time secret so the create-once flow is demoable.
    const rand = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    const prefix = input.env === "live" ? "azn_live_" : "azn_test_";
    return {
      id: `${prefix}${rand.slice(0, 16)}`,
      prefix,
      org_id: "org_demo",
      env: input.env,
      tier: input.tier ?? "default",
      is_active: true,
      shadow: input.shadow,
      created_at: new Date().toISOString(),
      secret: `${prefix}${rand}${rand}`.slice(0, prefix.length + 43),
    };
  }
  return call<CreatedApiKey>("POST", "/v1/keys", {
    env: input.env,
    shadow: input.shadow,
    ...(input.tier ? { tier: input.tier } : {}),
  });
}

export async function revokeKey(id: string): Promise<ApiKey | { id: string; is_active: false }> {
  if (!liveBackend()) return { id, is_active: false };
  return call<ApiKey>("POST", `/v1/keys/${encodeURIComponent(id)}/revoke`);
}

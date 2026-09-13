/** Seeded mock data so every screen renders without a running backend. When
 *  AUTHZ_BASE_URL + AUTHZ_API_KEY are set, lib/api.ts talks to authorize-svc instead. */
import type {
  ApiKey,
  BundleRef,
  Decision,
  Jwks,
  Policy,
  PolicyVersion,
} from "./contracts";

const AGENT = "procurement-agent-v2";

export const MOCK_JWKS: Jwks = {
  keys: [{ kty: "OKP", crv: "Ed25519", kid: "azn-sign-2026-08", x: "REPLACED-AT-RUNTIME", use: "sig", status: "active" }],
};

export const MOCK_POLICY: Policy = {
  id: "pol_01HXYZDEMO",
  org_id: "org_demo",
  name: "Procurement agent guardrails",
  agents: [AGENT],
  status: "published",
  active_version_hash: "polv_9f2a1c7e4b5d6a8f0c1e2d3b4a5f6e7d",
  created_at: "2026-08-20T09:00:00Z",
  updated_at: "2026-08-27T10:30:00Z",
  rules: [
    { rule_id: "per_txn_5k", type: "per_transaction_limit", params: { limit: "5000.00", currency: "USD" } },
    { rule_id: "vendor_allowlist", type: "vendor_allowlist", params: { allow: ["acme-supplies", "globex"] } },
    { rule_id: "agent_can_pay", type: "agent_permission", params: { agent: AGENT, actions: ["payment.create"] } },
    { rule_id: "monthly_budget", type: "rolling_budget", params: { window: "month", limit: "50000.00", currency: "USD" } },
  ],
};

export const MOCK_VERSIONS: PolicyVersion[] = [
  {
    version_hash: "polv_9f2a1c7e4b5d6a8f0c1e2d3b4a5f6e7d",
    policy_id: MOCK_POLICY.id,
    org_id: "org_demo",
    name: MOCK_POLICY.name,
    agents: MOCK_POLICY.agents,
    rules: MOCK_POLICY.rules,
    author: "alex@org-demo.example",
    published_at: "2026-08-27T10:30:00Z",
    parent_hash: "polv_11aa22bb33cc44dd55ee66ff77008811",
    signature: { algorithm: "Ed25519", key_id: "azn-sign-2026-08", value: "c2lnbmF0dXJl", canonicalization: "ti-policy-canon/1" },
  },
  {
    version_hash: "polv_11aa22bb33cc44dd55ee66ff77008811",
    policy_id: MOCK_POLICY.id,
    org_id: "org_demo",
    name: MOCK_POLICY.name,
    agents: MOCK_POLICY.agents,
    rules: MOCK_POLICY.rules.slice(0, 3),
    author: "alex@org-demo.example",
    published_at: "2026-08-20T09:05:00Z",
    signature: { algorithm: "Ed25519", key_id: "azn-sign-2026-08", value: "c2lnMg", canonicalization: "ti-policy-canon/1" },
  },
];

export const MOCK_ACTIVE: BundleRef = {
  org_id: "org_demo",
  policy_id: MOCK_POLICY.id,
  version_hash: MOCK_POLICY.active_version_hash!,
  updated_at: "2026-08-27T10:30:00Z",
};

function decision(
  id: string,
  verdict: Decision["verdict"],
  amount: string,
  summary: string,
  when: string,
  latency: number,
): Decision {
  return {
    decision_id: id,
    verdict,
    policy_version_hash: MOCK_POLICY.active_version_hash!,
    explanation: {
      summary,
      matched_rules:
        verdict === "DENY"
          ? [{ rule_id: "monthly_budget", type: "rolling_budget", result: "DENIED", detail: `spend_to_date + amount=${amount} > limit=50000.00 USD` }]
          : [{ rule_id: "per_txn_5k", type: "per_transaction_limit", result: "SATISFIED", detail: `amount=${amount} <= 5000.00 USD` }],
    },
    obligations: verdict === "APPROVE" ? [{ type: "capture_within", detail: "Capture after payment.", params: { ttl_seconds: 120 } }] : [],
    latency_ms: latency,
    evaluated_at: when,
    signature: { algorithm: "Ed25519", key_id: "azn-sign-2026-08", value: "REPLACED-AT-RUNTIME", canonicalization: "ti-decision-canon/1" },
    record_hash: `rh_${id.slice(-8)}`,
  };
}

export const MOCK_DECISIONS: Decision[] = [
  decision("01HXYZ8K3M9QF0R7S2T4V6W8XA", "APPROVE", "1200.00", "All rules satisfied for procurement-agent paying acme-supplies.", "2026-08-27T10:32:11Z", 7),
  decision("01HXYZ8K3M9QF0R7S2T4V6W900", "DENY", "9000.00", "Transaction exceeds the monthly budget for procurement-agent.", "2026-08-27T11:04:52Z", 6),
  decision("01HXYZ8K3M9QF0R7S2T4V6W9AA", "APPROVE", "480.00", "All rules satisfied.", "2026-08-27T12:15:03Z", 5),
  decision("01HXYZ8K3M9QF0R7S2T4V6W9BB", "REVIEW", "5200.00", "Above per-transaction limit; step-up review required.", "2026-08-27T13:41:20Z", 9),
];

export const MOCK_KEYS: ApiKey[] = [
  { id: "key_live_01", prefix: "azn_live_", org_id: "org_demo", is_active: true, shadow: false, scopes: ["authorize"], created_at: "2026-08-10T08:00:00Z", last_used_at: "2026-08-27T13:41:20Z" },
  { id: "key_test_01", prefix: "azn_test_", org_id: "org_demo", is_active: true, shadow: true, scopes: ["authorize"], created_at: "2026-08-12T08:00:00Z", last_used_at: "2026-08-26T09:12:00Z" },
];

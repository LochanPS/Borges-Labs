// Package contractsv1 contains the Go types for the AI Transaction Authorization
// Infrastructure /v1 contract.
//
// These structs are the Go binding of the frozen JSON Schemas under
// /contracts/schemas. They are the single source of truth for the wire shape used
// by authorize-svc, policy-svc, and the SDKs. Field order, json tags, and
// optionality mirror the schemas exactly.
//
// Money is represented as a string (MonetaryAmount), never a float, to preserve
// exact precision and to give the Ed25519 decision canonicalization a single stable
// textual form. See /docs/decision-canonicalization.md.
//
// Two signatures, kept distinct (ROADMAP A#1):
//   - Request authentication (caller -> us) is HMAC (symmetric), carried in HTTP
//     headers, NOT in these bodies.
//   - The Decision.Signature (us -> everyone) is Ed25519 (asymmetric), verifiable by
//     any third party against the published public key.
package contractsv1

// MonetaryAmount is a canonical decimal string (e.g. "5000.00"). Not a float.
type MonetaryAmount = string

// CurrencyCode is an ISO 4217 alphabetic code (e.g. "USD").
type CurrencyCode = string

// Verdict is the combined authorization outcome.
type Verdict string

const (
	VerdictApprove Verdict = "APPROVE"
	VerdictDeny    Verdict = "DENY"
	VerdictReview  Verdict = "REVIEW"
)

// PredicateResult is the outcome of a single predicate. UNAVAILABLE marks an
// enriched predicate that could not complete; its declared fail-mode then governs
// the combined verdict (never a fabricated SATISFIED).
type PredicateResult string

const (
	ResultSatisfied   PredicateResult = "SATISFIED"
	ResultDenied      PredicateResult = "DENIED"
	ResultReview      PredicateResult = "REVIEW"
	ResultUnavailable PredicateResult = "UNAVAILABLE"
)

// PredicateType enumerates the supported predicate types (6 local + stateful/enriched).
type PredicateType string

const (
	TypePerTransactionLimit  PredicateType = "per_transaction_limit"
	TypeVendorAllowlist      PredicateType = "vendor_allowlist"
	TypeVendorBlocklist      PredicateType = "vendor_blocklist"
	TypeAgentPermission      PredicateType = "agent_permission"
	TypeTimeWindow           PredicateType = "time_window"
	TypeJurisdictionCurrency PredicateType = "jurisdiction_currency"
	TypeRollingBudget        PredicateType = "rolling_budget"
	TypeSanctionsScreen      PredicateType = "sanctions_screen"
	TypeVendorRisk           PredicateType = "vendor_risk"
)

// TargetType is the kind of counterparty/resource an action is directed at.
type TargetType string

const (
	TargetVendor   TargetType = "vendor"
	TargetAccount  TargetType = "account"
	TargetAddress  TargetType = "address"
	TargetInternal TargetType = "internal"
	TargetUnknown  TargetType = "unknown"
)

// Target is the counterparty/resource the action is directed at.
type Target struct {
	Type TargetType `json:"type"`
	ID   string     `json:"id"`
}

// Counter is one accumulator reading injected by the orchestrator. Predicates read
// these values from the request; they never query the network themselves.
type Counter struct {
	ID          string         `json:"id"`
	Window      string         `json:"window"` // "day" | "month" | "rolling"
	WindowKey   string         `json:"window_key,omitempty"`
	SpendToDate MonetaryAmount `json:"spend_to_date"`
	Limit       MonetaryAmount `json:"limit"`
	Currency    CurrencyCode   `json:"currency"`
}

// CounterSnapshot is the orchestrator-injected point-in-time accumulator state that
// makes budget/velocity decisions deterministic and replayable (ROADMAP A#3, A#7).
type CounterSnapshot struct {
	AsOf     string    `json:"as_of"`
	Counters []Counter `json:"counters"`
}

// AuthorizeRequest is the body of POST /v1/authorize: the full, explicit input
// vector for a deterministic decision.
type AuthorizeRequest struct {
	AgentID        string                 `json:"agent_id"`
	Action         string                 `json:"action"`
	Amount         MonetaryAmount         `json:"amount"`
	Currency       CurrencyCode           `json:"currency"`
	Target         Target                 `json:"target"`
	Jurisdiction   string                 `json:"jurisdiction,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	IdempotencyKey string                 `json:"idempotency_key"`

	// EvaluatedAt and CounterSnapshot are ORCHESTRATOR-INJECTED. Clients should not
	// set them; they are part of the frozen, replayable input vector (ROADMAP A#7).
	EvaluatedAt     string           `json:"evaluated_at,omitempty"`
	CounterSnapshot *CounterSnapshot `json:"counter_snapshot,omitempty"`
}

// MatchedRule is one rule that participated in the decision, with the numbers that
// drove it (TRD §7).
type MatchedRule struct {
	RuleID   string                 `json:"rule_id"`
	Type     PredicateType          `json:"type"`
	Result   PredicateResult        `json:"result"`
	Detail   string                 `json:"detail"`
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

// Explanation is the structured reasoning attached to every decision.
type Explanation struct {
	Summary      string        `json:"summary"`
	MatchedRules []MatchedRule `json:"matched_rules"`
}

// Obligation is a condition the caller must honor for the verdict to hold.
type Obligation struct {
	Type   string                 `json:"type"`
	Detail string                 `json:"detail,omitempty"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// Signature is the ASYMMETRIC (Ed25519) signature over the Decision — the audit
// receipt verifiable by any third party against the published public key.
type Signature struct {
	Algorithm        string `json:"algorithm"` // fixed "Ed25519" for v1
	KeyID            string `json:"key_id"`
	Value            string `json:"value"` // base64url (unpadded)
	Canonicalization string `json:"canonicalization"`
}

// Decision is both the POST /v1/authorize response and the stored audit record.
type Decision struct {
	DecisionID        string       `json:"decision_id"`
	Verdict           Verdict      `json:"verdict"`
	PolicyVersionHash string       `json:"policy_version_hash"`
	Explanation       Explanation  `json:"explanation"`
	Obligations       []Obligation `json:"obligations"`
	LatencyMs         int          `json:"latency_ms"`
	EvaluatedAt       string       `json:"evaluated_at"`
	Signature         Signature    `json:"signature"`

	// Shadow marks an advisory (log-only) decision the caller must not enforce.
	Shadow bool `json:"shadow,omitempty"`

	// Record-only fields (audit read path, not part of the signed bytes).
	RecordHash        string `json:"record_hash,omitempty"`
	SignatureVerified *bool  `json:"signature_verified,omitempty"`
}

// ValidationItem is a field-level validation problem (RFC 7807 extension).
type ValidationItem struct {
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
}

// Problem is the RFC 7807 error body (Content-Type application/problem+json).
type Problem struct {
	Type     string           `json:"type"`
	Title    string           `json:"title"`
	Status   int              `json:"status"`
	Detail   string           `json:"detail,omitempty"`
	Instance string           `json:"instance,omitempty"`
	Code     string           `json:"code,omitempty"`
	Errors   []ValidationItem `json:"errors,omitempty"`
}

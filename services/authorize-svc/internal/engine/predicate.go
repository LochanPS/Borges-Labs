package engine

import (
	"math/big"
	"time"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Input is the normalized, fully-explicit evaluation vector a predicate sees. It is
// derived once from the AuthorizeRequest; predicates read only from it and never
// touch the wall clock, randomness, or the network (TRD §5 — determinism is enforced
// by construction for local predicates). EvaluatedAt is the orchestrator-injected
// timestamp, so a time-dependent predicate is still deterministic and replayable
// (ROADMAP A#7).
type Input struct {
	AgentID      string
	Action       string
	AmountRaw    string   // canonical decimal string, as received
	Amount       *big.Rat // parsed exact value; nil if AmountRaw was unparseable
	Currency     string
	Target       contractsv1.Target
	Jurisdiction string
	EvaluatedAt  time.Time
	Context      map[string]interface{}
}

// Result is a single predicate's contribution: an outcome plus the human-readable
// reason and the machine-readable evidence that drove it (TRD §7).
type Result struct {
	Outcome  Outcome
	Reason   string
	Evidence map[string]interface{}
}

// Predicate is a typed, versioned decision rule with a fixed interface (TRD §5).
// New rule types add a Predicate; the engine never changes.
type Predicate interface {
	// RuleID identifies the rule in the explanation.
	RuleID() string
	// Type is the predicate's contract type.
	Type() contractsv1.PredicateType
	// AppliesTo reports whether this rule is in scope for the given agent.
	AppliesTo(agentID string) bool
	// Evaluate purely maps the input to a result.
	Evaluate(in Input) Result
}

// base carries the fields every predicate shares: its id and its agent scope.
type base struct {
	ID     string
	Agents []string // empty = applies to every agent
}

func (b base) RuleID() string { return b.ID }

// AppliesTo returns true when the rule has no agent scope (applies to all) or the
// agent is explicitly listed.
func (b base) AppliesTo(agentID string) bool {
	if len(b.Agents) == 0 {
		return true
	}
	for _, a := range b.Agents {
		if a == agentID {
			return true
		}
	}
	return false
}

// parseMoney parses a canonical decimal string into an exact rational. Using big.Rat
// (never float) keeps comparisons exact and the evidence textual form stable for the
// eventual decision canonicalization.
func parseMoney(s string) (*big.Rat, bool) {
	r, ok := new(big.Rat).SetString(s)
	return r, ok
}

// contains reports whether v is in list.
func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

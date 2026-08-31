// Package engine implements the deterministic verdict combination algebra.
//
// This file is the SPECIFICATION of that algebra (types + the documented
// signature of Combine). The body of Combine is a Phase-1 stub that returns
// the zero Verdict on purpose, so the reference tests in verdict_test.go fail
// (TDD "red"). The real implementation lands in Phase 1; the tests define,
// unambiguously, what it must do.
//
// # Combination algebra (TRD §5, §21)
//
// A decision is the combination of N predicate results. The algebra is a pure,
// total, order-independent function of the multiset of results:
//
//  1. Resolve every predicate that could not complete (Outcome == Unavailable)
//     through its declared FailMode into an effective outcome:
//     - FailClosedDeny   -> Denied
//     - FailClosedReview -> Flagged (route to human)
//     - FailOpen         -> Satisfied   (customer opt-in ONLY, logged)
//     - "" (unspecified) -> Flagged     (safe default; never a fabricated satisfy)
//  2. Then apply strict precedence over the effective outcomes:
//     - any Denied         => DENY
//     - else any Flagged   => REVIEW
//     - else all Satisfied => APPROVE
//  3. An empty result set => DENY (deny-by-default, TRD §6/§20). There is no
//     authority to approve when no predicate granted any.
//
// Governing invariant (TRD §21): an Unavailable predicate NEVER becomes APPROVE
// on its own — the only path from Unavailable to a satisfy is an explicit,
// customer-declared FailOpen. The default and every fail-closed mode route to
// REVIEW or DENY. Never fabricate a CLEAR/satisfy for a predicate that did not
// actually complete.
//
// Determinism: no wall-clock, randomness, or I/O. The verdict is a pure
// function of the inputs.
//
// # Relationship to the ComplianceAPI verdict table
//
// The ComplianceAPI pack (PRODUCT-LINE-PLAN §5) is a subset of this algebra:
//
//	sanctions BLOCK / spend EXCEEDED / jurisdiction BLOCKED -> a Denied predicate -> DENY
//	fuzzy sanctions match                                   -> a Flagged predicate -> REVIEW
//	all clear + within limit                                -> all Satisfied       -> APPROVE
//	upstream TIMEOUT/UNAVAILABLE                             -> Unavailable, fail-closed -> REVIEW or DENY
//
// ComplianceAPI renders that fail-closed enriched verdict at its HTTP surface as
// UPSTREAM_UNAVAILABLE / 503; internally it is a fail-closed REVIEW or DENY.
package engine

// Verdict is the final decision emitted by the engine.
// The zero value is intentionally invalid so an unimplemented/miswired path is
// caught by tests rather than silently defaulting to a real verdict.
type Verdict string

const (
	// Approve: every applicable predicate was satisfied.
	Approve Verdict = "APPROVE"
	// Deny: at least one predicate hard-denied (or fail-closed to deny), or the
	// applicable set was empty (deny-by-default).
	Deny Verdict = "DENY"
	// Review: no hard deny, but at least one predicate flagged for human review
	// (or fail-closed to review).
	Review Verdict = "REVIEW"
)

// Outcome is the result of evaluating a single predicate.
type Outcome string

const (
	// Satisfied: the predicate's condition held.
	Satisfied Outcome = "SATISFIED"
	// Denied: the predicate hard-denied the transaction.
	Denied Outcome = "DENIED"
	// Flagged: the predicate requests human review (neither satisfy nor deny).
	Flagged Outcome = "REVIEW"
	// Unavailable: an (enriched) predicate could not complete — timeout, upstream
	// error, or a stateful dependency (Redis) down. Governed by FailMode.
	Unavailable Outcome = "UNAVAILABLE"
)

// FailMode declares how an Unavailable predicate is resolved. It is consulted
// ONLY when Outcome == Unavailable. The zero value ("") means unspecified and
// resolves to the safe default (Flagged / REVIEW).
type FailMode string

const (
	// FailClosedReview: Unavailable -> Flagged (route to a human). Safe default.
	FailClosedReview FailMode = "FAIL_CLOSED_REVIEW"
	// FailClosedDeny: Unavailable -> Denied. Safest; for hard-regulated predicates.
	FailClosedDeny FailMode = "FAIL_CLOSED_DENY"
	// FailOpen: Unavailable -> Satisfied. Customer opt-in ONLY, must be logged.
	// This is the sole path from a non-completing predicate to a satisfy.
	FailOpen FailMode = "FAIL_OPEN"
)

// PredicateResult is one predicate's contribution to the decision.
type PredicateResult struct {
	// RuleID identifies the predicate (for explanation assembly, not the algebra).
	RuleID string
	// Enriched marks a network/enrichment predicate (vs a local, always-available
	// one). Informational for explainability; the algebra keys off Outcome+FailMode.
	Enriched bool
	// Outcome is this predicate's result.
	Outcome Outcome
	// FailMode governs resolution when Outcome == Unavailable; ignored otherwise.
	FailMode FailMode
}

// Combine folds predicate results into a single Verdict per the algebra
// documented on this package. Pure, total, and order-independent.
func Combine(results []PredicateResult) Verdict {
	// Deny-by-default: with no predicate granting anything, there is no authority
	// to approve (TRD §6/§20).
	if len(results) == 0 {
		return Deny
	}

	sawFlag := false
	for _, r := range results {
		switch effectiveOutcome(r) {
		case Denied:
			// Hard deny short-circuits: any deny dominates every other outcome.
			return Deny
		case Flagged:
			sawFlag = true
		case Satisfied:
			// Contributes nothing on its own; approval requires the absence of any
			// deny or flag across the whole set.
		}
	}

	if sawFlag {
		return Review
	}
	return Approve
}

// effectiveOutcome resolves a single result into one of Satisfied/Denied/Flagged.
// An Unavailable predicate is resolved through its declared FailMode; every other
// outcome passes through unchanged. The only path from Unavailable to Satisfied is
// an explicit customer-declared FailOpen — the governing invariant (TRD §21).
func effectiveOutcome(r PredicateResult) Outcome {
	if r.Outcome != Unavailable {
		return r.Outcome
	}
	switch r.FailMode {
	case FailClosedDeny:
		return Denied
	case FailOpen:
		return Satisfied
	case FailClosedReview:
		return Flagged
	default:
		// Unspecified (or any unknown) fail mode: safe default, never a fabricated
		// satisfy for a predicate that did not complete.
		return Flagged
	}
}

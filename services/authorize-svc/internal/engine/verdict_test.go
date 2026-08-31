package engine

// Reference tests for the verdict combination algebra (TRD §5, §21; TDD "red").
//
// These tests currently FAIL: engine.Combine is a Phase-1 stub returning the
// zero Verdict. The intended behavior is fully specified by the case names and
// expectations below; Phase 1 implements Combine to make them pass at 100%
// branch coverage (TRD §19, non-negotiable).

import "testing"

// helpers keep the tables readable; each builds one predicate result.
func local(outcome Outcome) PredicateResult {
	return PredicateResult{RuleID: "local", Enriched: false, Outcome: outcome}
}
func enriched(id string, outcome Outcome, fm FailMode) PredicateResult {
	return PredicateResult{RuleID: id, Enriched: true, Outcome: outcome, FailMode: fm}
}

func TestCombine(t *testing.T) {
	tests := []struct {
		name    string
		results []PredicateResult
		want    Verdict
	}{
		// ---- core precedence: DENY > REVIEW > APPROVE --------------------------
		{
			name:    "all_satisfied_approves",
			results: []PredicateResult{local(Satisfied), local(Satisfied), local(Satisfied)},
			want:    Approve,
		},
		{
			name:    "single_satisfied_approves",
			results: []PredicateResult{local(Satisfied)},
			want:    Approve,
		},
		{
			name:    "any_denied_denies",
			results: []PredicateResult{local(Satisfied), local(Denied), local(Satisfied)},
			want:    Deny,
		},
		{
			name:    "any_flagged_reviews_when_no_deny",
			results: []PredicateResult{local(Satisfied), local(Flagged), local(Satisfied)},
			want:    Review,
		},
		{
			name:    "deny_beats_flag",
			results: []PredicateResult{local(Flagged), local(Denied)},
			want:    Deny,
		},
		{
			name:    "flag_beats_satisfy",
			results: []PredicateResult{local(Satisfied), local(Flagged)},
			want:    Review,
		},
		{
			name:    "multiple_denies_still_deny",
			results: []PredicateResult{local(Denied), local(Denied)},
			want:    Deny,
		},
		{
			name:    "order_independent_deny_first",
			results: []PredicateResult{local(Denied), local(Flagged), local(Satisfied)},
			want:    Deny,
		},
		{
			name:    "order_independent_flag_first",
			results: []PredicateResult{local(Flagged), local(Satisfied), local(Denied)},
			want:    Deny,
		},

		// ---- deny-by-default --------------------------------------------------
		{
			name:    "empty_set_denies_by_default",
			results: []PredicateResult{},
			want:    Deny,
		},
		{
			name:    "nil_set_denies_by_default",
			results: nil,
			want:    Deny,
		},

		// ---- Unavailable resolved by declared FailMode ------------------------
		{
			name:    "unavailable_fail_closed_review",
			results: []PredicateResult{local(Satisfied), enriched("sanctions", Unavailable, FailClosedReview)},
			want:    Review,
		},
		{
			name:    "unavailable_fail_closed_deny",
			results: []PredicateResult{local(Satisfied), enriched("sanctions", Unavailable, FailClosedDeny)},
			want:    Deny,
		},
		{
			name:    "unavailable_unspecified_fail_mode_defaults_to_review",
			results: []PredicateResult{local(Satisfied), enriched("sanctions", Unavailable, FailMode(""))},
			want:    Review,
		},
		{
			name:    "unavailable_fail_open_satisfies_when_rest_satisfied",
			results: []PredicateResult{local(Satisfied), enriched("vendor_risk", Unavailable, FailOpen)},
			want:    Approve,
		},
		{
			name:    "fail_open_does_not_mask_a_real_deny",
			results: []PredicateResult{local(Denied), enriched("vendor_risk", Unavailable, FailOpen)},
			want:    Deny,
		},
		{
			name:    "fail_open_does_not_mask_a_real_flag",
			results: []PredicateResult{local(Flagged), enriched("vendor_risk", Unavailable, FailOpen)},
			want:    Review,
		},
		{
			name:    "deny_beats_unavailable_fail_closed_review",
			results: []PredicateResult{local(Denied), enriched("sanctions", Unavailable, FailClosedReview)},
			want:    Deny,
		},
		{
			name:    "two_unavailables_deny_beats_review",
			results: []PredicateResult{enriched("a", Unavailable, FailClosedReview), enriched("b", Unavailable, FailClosedDeny)},
			want:    Deny,
		},
		{
			name:    "local_unavailable_also_fails_closed",
			results: []PredicateResult{{RuleID: "budget", Enriched: false, Outcome: Unavailable, FailMode: FailClosedReview}},
			want:    Review,
		},

		// ---- ComplianceAPI verdict table (PRODUCT-LINE-PLAN §5) ---------------
		// The ComplianceAPI pack is a subset of this algebra.
		{
			name: "compliance_ofac_block_denies",
			results: []PredicateResult{
				enriched("sanctions_ofac", Denied, FailClosedReview),
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
			},
			want: Deny,
		},
		{
			name: "compliance_eu_block_denies",
			results: []PredicateResult{
				enriched("sanctions_ofac", Satisfied, FailClosedReview),
				enriched("sanctions_eu", Denied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
			},
			want: Deny,
		},
		{
			name: "compliance_spend_exceeded_denies",
			results: []PredicateResult{
				enriched("sanctions_ofac", Satisfied, FailClosedReview),
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
				local(Denied), // spend EXCEEDED
			},
			want: Deny,
		},
		{
			name: "compliance_jurisdiction_blocked_denies",
			results: []PredicateResult{
				enriched("sanctions_ofac", Satisfied, FailClosedReview),
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
				local(Denied), // jurisdiction BLOCKED
			},
			want: Deny,
		},
		{
			name: "compliance_fuzzy_match_reviews",
			results: []PredicateResult{
				enriched("sanctions_ofac", Flagged, FailClosedReview), // 0.65 fuzzy match
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
			},
			want: Review,
		},
		{
			name: "compliance_all_clear_within_limit_approves",
			results: []PredicateResult{
				enriched("sanctions_ofac", Satisfied, FailClosedReview),
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
				local(Satisfied), // spend WITHIN_LIMIT
			},
			want: Approve,
		},
		{
			name: "compliance_ofac_timeout_fail_closed_reviews",
			results: []PredicateResult{
				enriched("sanctions_ofac", Unavailable, FailClosedReview), // upstream TIMEOUT
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
			},
			want: Review,
		},
		{
			name: "compliance_ofac_timeout_fail_closed_deny_variant",
			results: []PredicateResult{
				enriched("sanctions_ofac", Unavailable, FailClosedDeny), // regulated predicate, deny variant
				enriched("sanctions_eu", Satisfied, FailClosedReview),
				enriched("sanctions_un", Satisfied, FailClosedReview),
			},
			want: Deny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Combine(tt.results)
			if got != tt.want {
				t.Errorf("Combine() = %q, want %q", got, tt.want)
			}
		})
	}
}

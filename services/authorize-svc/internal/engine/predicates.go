package engine

import (
	"fmt"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// This file holds the six LOCAL predicate types (TRD §5–6, ROADMAP Task 1.4). All
// are pure and side-effect-free: no network, no wall clock (time comes from
// Input.EvaluatedAt), no randomness. Budgets and sanctions are OUT of scope here —
// they are stateful/enriched predicates (Phase 3 / enrichment).

// --- per_transaction_limit ---------------------------------------------------

// PerTransactionLimit denies a single transaction whose amount exceeds Max. A
// currency mismatch between the rule and the request is REVIEW, not a silent
// numeric compare across currencies.
type PerTransactionLimit struct {
	base
	MaxRaw   string
	Currency string // currency the limit is denominated in ("" = any)
}

func (PerTransactionLimit) Type() contractsv1.PredicateType {
	return contractsv1.TypePerTransactionLimit
}

func (p PerTransactionLimit) Evaluate(in Input) Result {
	max, ok := parseMoney(p.MaxRaw)
	if !ok {
		return Result{Outcome: Flagged, Reason: "per-transaction limit is misconfigured (unparseable amount)",
			Evidence: map[string]interface{}{"limit": p.MaxRaw}}
	}
	if p.Currency != "" && p.Currency != in.Currency {
		return Result{Outcome: Flagged,
			Reason:   fmt.Sprintf("limit is in %s but transaction is in %s; cannot compare", p.Currency, in.Currency),
			Evidence: map[string]interface{}{"limit_currency": p.Currency, "txn_currency": in.Currency}}
	}
	if in.Amount == nil {
		return Result{Outcome: Flagged, Reason: "transaction amount is unparseable",
			Evidence: map[string]interface{}{"amount": in.AmountRaw}}
	}
	ev := map[string]interface{}{"amount": in.AmountRaw, "limit": p.MaxRaw, "currency": in.Currency}
	if in.Amount.Cmp(max) > 0 {
		return Result{Outcome: Denied,
			Reason:   fmt.Sprintf("amount=%s exceeds per-transaction limit=%s %s", in.AmountRaw, p.MaxRaw, in.Currency),
			Evidence: ev}
	}
	return Result{Outcome: Satisfied,
		Reason:   fmt.Sprintf("amount=%s within per-transaction limit=%s %s", in.AmountRaw, p.MaxRaw, in.Currency),
		Evidence: ev}
}

// --- vendor_allowlist --------------------------------------------------------

// VendorAllowlist requires a vendor target to be on the list. Non-vendor targets
// are out of this rule's scope and pass.
type VendorAllowlist struct {
	base
	Vendors []string
}

func (VendorAllowlist) Type() contractsv1.PredicateType { return contractsv1.TypeVendorAllowlist }

func (p VendorAllowlist) Evaluate(in Input) Result {
	if in.Target.Type != contractsv1.TargetVendor {
		return Result{Outcome: Satisfied, Reason: "target is not a vendor; allowlist not applicable",
			Evidence: map[string]interface{}{"target_type": string(in.Target.Type)}}
	}
	ev := map[string]interface{}{"vendor": in.Target.ID}
	if contains(p.Vendors, in.Target.ID) {
		return Result{Outcome: Satisfied, Reason: fmt.Sprintf("vendor %q is allowlisted", in.Target.ID), Evidence: ev}
	}
	return Result{Outcome: Denied, Reason: fmt.Sprintf("vendor %q is not on the allowlist", in.Target.ID), Evidence: ev}
}

// --- vendor_blocklist --------------------------------------------------------

// VendorBlocklist denies a vendor target on the list. Non-vendor targets pass.
type VendorBlocklist struct {
	base
	Vendors []string
}

func (VendorBlocklist) Type() contractsv1.PredicateType { return contractsv1.TypeVendorBlocklist }

func (p VendorBlocklist) Evaluate(in Input) Result {
	if in.Target.Type != contractsv1.TargetVendor {
		return Result{Outcome: Satisfied, Reason: "target is not a vendor; blocklist not applicable",
			Evidence: map[string]interface{}{"target_type": string(in.Target.Type)}}
	}
	ev := map[string]interface{}{"vendor": in.Target.ID}
	if contains(p.Vendors, in.Target.ID) {
		return Result{Outcome: Denied, Reason: fmt.Sprintf("vendor %q is blocklisted", in.Target.ID), Evidence: ev}
	}
	return Result{Outcome: Satisfied, Reason: fmt.Sprintf("vendor %q is not blocklisted", in.Target.ID), Evidence: ev}
}

// --- agent_permission --------------------------------------------------------

// AgentPermission constrains which actions an agent may take and, optionally, which
// targets it may act on. Empty lists mean "no constraint on this dimension".
type AgentPermission struct {
	base
	AllowedActions []string
	AllowedTargets []string // target ids; empty = any target
}

func (AgentPermission) Type() contractsv1.PredicateType { return contractsv1.TypeAgentPermission }

func (p AgentPermission) Evaluate(in Input) Result {
	if len(p.AllowedActions) > 0 && !contains(p.AllowedActions, in.Action) {
		return Result{Outcome: Denied,
			Reason:   fmt.Sprintf("agent %q may not perform action %q", in.AgentID, in.Action),
			Evidence: map[string]interface{}{"action": in.Action, "allowed_actions": p.AllowedActions}}
	}
	if len(p.AllowedTargets) > 0 && !contains(p.AllowedTargets, in.Target.ID) {
		return Result{Outcome: Denied,
			Reason:   fmt.Sprintf("agent %q may not act on target %q", in.AgentID, in.Target.ID),
			Evidence: map[string]interface{}{"target": in.Target.ID, "allowed_targets": p.AllowedTargets}}
	}
	return Result{Outcome: Satisfied,
		Reason:   fmt.Sprintf("agent %q is permitted action %q on target %q", in.AgentID, in.Action, in.Target.ID),
		Evidence: map[string]interface{}{"action": in.Action, "target": in.Target.ID}}
}

// --- time_window -------------------------------------------------------------

// TimeWindow restricts transactions to an allowed time-of-day window (and optional
// weekdays), evaluated against the injected EvaluatedAt in UTC. Outside the window is
// DENY. Start/End are minutes-of-day in [0,1440); the window is [Start, End). A
// window that wraps midnight (End <= Start) is treated as spanning midnight.
type TimeWindow struct {
	base
	StartMinute int
	EndMinute   int
	// Weekdays, if non-empty, restricts to those days (time.Weekday: Sunday=0).
	Weekdays []int
}

func (TimeWindow) Type() contractsv1.PredicateType { return contractsv1.TypeTimeWindow }

func (p TimeWindow) Evaluate(in Input) Result {
	t := in.EvaluatedAt.UTC()
	minute := t.Hour()*60 + t.Minute()

	ev := map[string]interface{}{
		"evaluated_at": t.Format("15:04"),
		"window":       fmt.Sprintf("%02d:%02d-%02d:%02d", p.StartMinute/60, p.StartMinute%60, p.EndMinute/60, p.EndMinute%60),
		"weekday":      t.Weekday().String(),
	}

	if len(p.Weekdays) > 0 && !containsInt(p.Weekdays, int(t.Weekday())) {
		return Result{Outcome: Denied, Reason: fmt.Sprintf("%s is outside the allowed weekdays", t.Weekday()), Evidence: ev}
	}
	if !withinWindow(minute, p.StartMinute, p.EndMinute) {
		return Result{Outcome: Denied, Reason: fmt.Sprintf("%s is outside the allowed time window", t.Format("15:04")), Evidence: ev}
	}
	return Result{Outcome: Satisfied, Reason: fmt.Sprintf("%s is within the allowed time window", t.Format("15:04")), Evidence: ev}
}

// withinWindow reports whether minute is in [start, end), handling a window that
// wraps past midnight (end <= start).
func withinWindow(minute, start, end int) bool {
	if start == end {
		return true // full-day window
	}
	if start < end {
		return minute >= start && minute < end
	}
	// Wraps midnight, e.g. 22:00-06:00.
	return minute >= start || minute < end
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// --- jurisdiction_currency ---------------------------------------------------

// JurisdictionCurrency restricts which currencies are permitted per jurisdiction.
// Allowed maps a jurisdiction (ISO 3166-1 alpha-2) to its permitted currency codes.
// A jurisdiction absent from the map is unconstrained (pass).
type JurisdictionCurrency struct {
	base
	Allowed map[string][]string
}

func (JurisdictionCurrency) Type() contractsv1.PredicateType {
	return contractsv1.TypeJurisdictionCurrency
}

func (p JurisdictionCurrency) Evaluate(in Input) Result {
	allowed, constrained := p.Allowed[in.Jurisdiction]
	if in.Jurisdiction == "" || !constrained {
		return Result{Outcome: Satisfied, Reason: "jurisdiction is unconstrained",
			Evidence: map[string]interface{}{"jurisdiction": in.Jurisdiction, "currency": in.Currency}}
	}
	ev := map[string]interface{}{"jurisdiction": in.Jurisdiction, "currency": in.Currency, "allowed": allowed}
	if contains(allowed, in.Currency) {
		return Result{Outcome: Satisfied,
			Reason:   fmt.Sprintf("currency %s is permitted in %s", in.Currency, in.Jurisdiction),
			Evidence: ev}
	}
	return Result{Outcome: Denied,
		Reason:   fmt.Sprintf("currency %s is not permitted in %s", in.Currency, in.Jurisdiction),
		Evidence: ev}
}

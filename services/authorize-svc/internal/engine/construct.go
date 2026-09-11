package engine

// Exported constructors for the six local predicates. They let another package
// (internal/policy, which loads a policy from JSON) build predicates without
// reaching into the unexported base field. Keeping base unexported preserves the
// invariant that a Predicate is immutable once constructed.

// NewPerTransactionLimit builds a per_transaction_limit predicate. currency ""
// means the limit applies to any currency.
func NewPerTransactionLimit(id string, agents []string, maxRaw, currency string) PerTransactionLimit {
	return PerTransactionLimit{base: base{ID: id, Agents: agents}, MaxRaw: maxRaw, Currency: currency}
}

// NewVendorAllowlist builds a vendor_allowlist predicate.
func NewVendorAllowlist(id string, agents, vendors []string) VendorAllowlist {
	return VendorAllowlist{base: base{ID: id, Agents: agents}, Vendors: vendors}
}

// NewVendorBlocklist builds a vendor_blocklist predicate.
func NewVendorBlocklist(id string, agents, vendors []string) VendorBlocklist {
	return VendorBlocklist{base: base{ID: id, Agents: agents}, Vendors: vendors}
}

// NewAgentPermission builds an agent_permission predicate. Empty lists mean "no
// constraint on this dimension".
func NewAgentPermission(id string, agents, allowedActions, allowedTargets []string) AgentPermission {
	return AgentPermission{base: base{ID: id, Agents: agents}, AllowedActions: allowedActions, AllowedTargets: allowedTargets}
}

// NewTimeWindow builds a time_window predicate. Minutes are minutes-of-day in
// [0,1440); weekdays (time.Weekday: Sunday=0) empty means every day.
func NewTimeWindow(id string, agents []string, startMinute, endMinute int, weekdays []int) TimeWindow {
	return TimeWindow{base: base{ID: id, Agents: agents}, StartMinute: startMinute, EndMinute: endMinute, Weekdays: weekdays}
}

// NewJurisdictionCurrency builds a jurisdiction_currency predicate.
func NewJurisdictionCurrency(id string, agents []string, allowed map[string][]string) JurisdictionCurrency {
	return JurisdictionCurrency{base: base{ID: id, Agents: agents}, Allowed: allowed}
}

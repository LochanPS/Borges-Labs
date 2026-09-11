package policyctl

import "github.com/trust-infra/authorize-svc/internal/ulid"

// idPrefix labels a policy id (distinct from a version hash's polv_). Policy ids are
// ULIDs so they are unique and lexicographically sortable by creation time.
const idPrefix = "pol_"

// newPolicyID mints a fresh policy id.
func newPolicyID() string { return idPrefix + ulid.New() }

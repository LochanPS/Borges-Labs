package policyctl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
)

// newTestService builds a Service over a MemStore and a real Ed25519 signer, returning
// the service and the keyring so tests can verify version signatures against the
// published public key.
func newTestService(t *testing.T) (*Service, *signing.Keyring) {
	t.Helper()
	kr := signing.NewKeyring()
	if _, err := kr.GenerateActive(); err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := kr.Signer()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// Deterministic clock so republish/rollback do not race on identical timestamps.
	var tick int64
	svc := NewService(NewMemStore(), signer).
		WithClock(func() time.Time { tick++; return time.Unix(1_700_000_000+tick, 0).UTC() })
	return svc, kr
}

func sampleRules() []Rule {
	max := "5000.00"
	start, end := 540, 1020
	return []Rule{
		{ID: "limit", Type: "per_transaction_limit", Max: max, Currency: "USD"},
		{ID: "perm", Type: "agent_permission", AllowedActions: []string{"payment.create"}},
		{ID: "hours", Type: "time_window", StartMinute: &start, EndMinute: &end},
		// A placeholder (Phase 3) rule: valid to author + sign now, not enforced yet.
		{ID: "monthly", Type: "rolling_budget", Window: "month", Limit: "50000.00", Currency: "USD"},
	}
}

// ACCEPTANCE 1: author a policy, publish it, get a version hash; and the signed
// version verifies against the published public key.
func TestPublish_AuthorGetHashAndVerify(t *testing.T) {
	svc, kr := newTestService(t)
	ctx := context.Background()

	p, err := svc.Create(ctx, "org1", "vendor payments", []string{"agent-a"}, sampleRules())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Status != StatusDraft {
		t.Errorf("new policy status = %q, want draft", p.Status)
	}

	v, err := svc.Publish(ctx, "org1", p.ID, "alice")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !strings.HasPrefix(v.VersionHash, versionPrefix) {
		t.Errorf("version hash = %q, want %s prefix", v.VersionHash, versionPrefix)
	}
	if v.ParentHash != "" {
		t.Errorf("first version parent = %q, want empty", v.ParentHash)
	}

	// The policy is now published and points at the version.
	got, _ := svc.Get(ctx, "org1", p.ID)
	if got.Status != StatusPublished || got.ActiveVersionHash != v.VersionHash {
		t.Errorf("after publish: status=%q active=%q, want published/%s", got.Status, got.ActiveVersionHash, v.VersionHash)
	}

	// The version's Ed25519 signature verifies against the published public key.
	pub, ok := kr.PublicKey(v.Signature.KeyID)
	if !ok {
		t.Fatalf("public key %q not published", v.Signature.KeyID)
	}
	if err := VerifyVersion(v, pub); err != nil {
		t.Errorf("VerifyVersion: %v", err)
	}
}

// ACCEPTANCE 2: edit + republish creates a NEW immutable version; the old one is
// unchanged and both are listed.
func TestPublish_EditCreatesNewImmutableVersion(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	v1, err := svc.Publish(ctx, "org1", p.ID, "alice")
	if err != nil {
		t.Fatalf("publish v1: %v", err)
	}

	// Edit the working copy: lower the limit.
	edited := sampleRules()
	edited[0].Max = "1000.00"
	if _, err := svc.Update(ctx, "org1", p.ID, "", nil, edited); err != nil {
		t.Fatalf("update: %v", err)
	}
	v2, err := svc.Publish(ctx, "org1", p.ID, "bob")
	if err != nil {
		t.Fatalf("publish v2: %v", err)
	}

	if v1.VersionHash == v2.VersionHash {
		t.Fatal("edit did not produce a new version hash")
	}
	if v2.ParentHash != v1.VersionHash {
		t.Errorf("v2 parent = %q, want v1 %q", v2.ParentHash, v1.VersionHash)
	}

	versions, _ := svc.ListVersions(ctx, "org1", p.ID)
	if len(versions) != 2 {
		t.Fatalf("versions = %d, want 2", len(versions))
	}
	if versions[0].VersionHash != v2.VersionHash {
		t.Errorf("newest version = %q, want v2 %q", versions[0].VersionHash, v2.VersionHash)
	}

	// v1 is immutable: fetching it still shows the original limit.
	stored, err := svc.store.GetVersion(ctx, "org1", p.ID, v1.VersionHash)
	if err != nil {
		t.Fatalf("get v1: %v", err)
	}
	if stored.Rules[0].Max != "5000.00" {
		t.Errorf("v1 limit mutated to %q, want 5000.00", stored.Rules[0].Max)
	}
}

// Republishing byte-identical content is idempotent: same hash, no second row.
func TestPublish_IdenticalIsIdempotent(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	v1, _ := svc.Publish(ctx, "org1", p.ID, "alice")
	v2, err := svc.Publish(ctx, "org1", p.ID, "alice")
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if v1.VersionHash != v2.VersionHash {
		t.Errorf("identical content got different hashes: %q vs %q", v1.VersionHash, v2.VersionHash)
	}
	if versions, _ := svc.ListVersions(ctx, "org1", p.ID); len(versions) != 1 {
		t.Errorf("versions = %d, want 1 (idempotent republish)", len(versions))
	}
}

// ACCEPTANCE 3: an invalid policy is rejected with a clear, field-pointed error.
func TestPublish_InvalidRejected(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	bad := []Rule{
		{ID: "limit", Type: "per_transaction_limit"}, // missing max
		{ID: "limit", Type: "vendor_blocklist"},      // duplicate id
		{ID: "huh", Type: "not_a_real_type"},         // unknown type
	}
	p, _ := svc.Create(ctx, "org1", "p", nil, bad)
	_, err := svc.Publish(ctx, "org1", p.ID, "alice")
	if err == nil {
		t.Fatal("publish of invalid policy succeeded, want rejection")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error type = %T, want *ValidationError", err)
	}
	if len(ve.Problems) == 0 {
		t.Fatal("ValidationError carries no problems")
	}
	msg := ve.Error()
	if !strings.Contains(msg, "duplicate rule id") {
		t.Errorf("error does not mention the duplicate id: %s", msg)
	}
	// No version was minted.
	if versions, _ := svc.store.ListVersions(ctx, "org1", p.ID); len(versions) != 0 {
		t.Errorf("invalid publish minted %d versions, want 0", len(versions))
	}
}

// ACCEPTANCE 4: rollback restores a prior version (active pointer + working copy) and
// mints no new version.
func TestRollback_RestoresPriorVersion(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	v1, _ := svc.Publish(ctx, "org1", p.ID, "alice")

	edited := sampleRules()
	edited[0].Max = "1000.00"
	svc.Update(ctx, "org1", p.ID, "", nil, edited)
	v2, _ := svc.Publish(ctx, "org1", p.ID, "bob")

	if active, _ := svc.Active(ctx, "org1", p.ID); active.VersionHash != v2.VersionHash {
		t.Fatalf("pre-rollback active = %q, want v2", active.VersionHash)
	}

	restored, err := svc.Rollback(ctx, "org1", p.ID, v1.VersionHash)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if restored.VersionHash != v1.VersionHash {
		t.Errorf("rollback returned %q, want v1 %q", restored.VersionHash, v1.VersionHash)
	}

	active, _ := svc.Active(ctx, "org1", p.ID)
	if active.VersionHash != v1.VersionHash {
		t.Errorf("post-rollback active = %q, want v1 %q", active.VersionHash, v1.VersionHash)
	}
	// Working copy is restored to v1's content.
	wc, _ := svc.Get(ctx, "org1", p.ID)
	if wc.Rules[0].Max != "5000.00" {
		t.Errorf("working-copy limit after rollback = %q, want 5000.00", wc.Rules[0].Max)
	}
	// No new version row created by rollback.
	if versions, _ := svc.ListVersions(ctx, "org1", p.ID); len(versions) != 2 {
		t.Errorf("versions after rollback = %d, want 2", len(versions))
	}
}

// Rollback to a hash that is not a version of this policy is rejected.
func TestRollback_UnknownVersionRejected(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	svc.Publish(ctx, "org1", p.ID, "alice")
	if _, err := svc.Rollback(ctx, "org1", p.ID, "polv_deadbeef"); !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("rollback to unknown hash err = %v, want ErrVersionNotFound", err)
	}
}

// Tampering with any signed field breaks verification (the audit-receipt property).
func TestVerifyVersion_TamperFails(t *testing.T) {
	svc, kr := newTestService(t)
	ctx := context.Background()
	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	v, _ := svc.Publish(ctx, "org1", p.ID, "alice")
	pub, _ := kr.PublicKey(v.Signature.KeyID)

	if err := VerifyVersion(v, pub); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}
	tampered := *v
	tampered.Rules = append([]Rule(nil), v.Rules...)
	tampered.Rules[0].Max = "999999.00"
	if err := VerifyVersion(&tampered, pub); err == nil {
		t.Error("verification passed on a tampered version, want failure")
	}
}

// Org scoping: one org cannot read another org's policy.
func TestOrgScoping(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	p, _ := svc.Create(ctx, "org1", "p", nil, sampleRules())
	if _, err := svc.Get(ctx, "org2", p.ID); !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("cross-org get err = %v, want ErrPolicyNotFound", err)
	}
}

// The checked-in example policy must validate against the schema (drift guard on the
// docs/examples, same intent as the contracts/examples decision samples).
func TestExamplePolicy_Validates(t *testing.T) {
	raw, err := os.ReadFile("../../../../contracts/examples/policy.example.json")
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	var doc struct {
		OrgID  string   `json:"org_id"`
		Name   string   `json:"name"`
		Agents []string `json:"agents"`
		Rules  []Rule   `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal example: %v", err)
	}
	if err := Validate(doc.OrgID, doc.Name, doc.Agents, doc.Rules); err != nil {
		t.Errorf("example policy failed validation: %v", err)
	}
}

// The embedded schema must stay byte-identical to the canonical contract copy.
func TestSchema_NoDriftFromContract(t *testing.T) {
	canonical, err := os.ReadFile("../../../../contracts/schemas/policy.schema.json")
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	if string(canonical) != string(schemaJSON) {
		t.Error("internal/policyctl/policy.schema.json has drifted from contracts/schemas/policy.schema.json; re-copy it")
	}
}

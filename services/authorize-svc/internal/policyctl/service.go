package policyctl

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/trust-infra/authorize-svc/internal/signing"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// Signer signs a canonical policy-version message with an Ed25519 key. Satisfied by
// *signing.Signer; an interface here keeps the Service testable and decoupled.
type Signer interface {
	SignDetached(canonicalization string, msg []byte) contractsv1.Signature
}

// Service is the control-plane policy API surface as pure domain logic (no HTTP). It
// authors and edits mutable working copies and, on publish, mints immutable signed
// versions. The Task 2.2 HTTP layer wraps this without changing it.
type Service struct {
	store  Store
	signer Signer
	now    func() time.Time
	newID  func() string
}

// *signing.Signer satisfies Signer.
var _ Signer = (*signing.Signer)(nil)

// NewService builds a Service over a Store and a Signer.
func NewService(store Store, signer Signer) *Service {
	return &Service{
		store:  store,
		signer: signer,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  newPolicyID,
	}
}

// WithClock overrides the wall clock (tests). Returns s for chaining.
func (s *Service) WithClock(now func() time.Time) *Service { s.now = now; return s }

// WithIDFunc overrides policy-id generation (tests). Returns s for chaining.
func (s *Service) WithIDFunc(fn func() string) *Service { s.newID = fn; return s }

// Create authors a new DRAFT policy. Rules are accepted as-is; validation is enforced
// authoritatively at Publish (a draft may be a work in progress). Identity fields are
// checked immediately so a policy always has an org and a name.
func (s *Service) Create(ctx context.Context, orgID, name string, agents []string, rules []Rule) (*Policy, error) {
	if orgID == "" {
		return nil, &ValidationError{Problems: []Problem{{Pointer: "/org_id", Detail: "org_id is required"}}}
	}
	if name == "" {
		return nil, &ValidationError{Problems: []Problem{{Pointer: "/name", Detail: "name is required"}}}
	}
	now := s.now()
	p := &Policy{
		ID:        s.newID(),
		OrgID:     orgID,
		Name:      name,
		Agents:    agents,
		Rules:     rules,
		Status:    StatusDraft,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.store.CreatePolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Get returns a policy's current working copy.
func (s *Service) Get(ctx context.Context, orgID, id string) (*Policy, error) {
	return s.store.GetPolicy(ctx, orgID, id)
}

// Update replaces a policy's working-copy fields (name, agents, rules). It does not
// publish and does not touch the active version — the previously published version
// keeps serving until the next Publish. Status is unchanged (a policy that was
// published stays published; a draft stays draft).
func (s *Service) Update(ctx context.Context, orgID, id, name string, agents []string, rules []Rule) (*Policy, error) {
	p, err := s.store.GetPolicy(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if name != "" {
		p.Name = name
	}
	p.Agents = agents
	p.Rules = rules
	p.UpdatedAt = s.now()
	if err := s.store.UpdatePolicy(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Publish validates the working copy, mints an immutable content-hash version, signs
// it (Ed25519), stores it, and designates it active. Republishing byte-identical
// content is idempotent: the same version hash is produced, PutVersion dedups, and the
// existing (already-signed) version is returned. Any edit yields a new hash and a new
// version. Returns a *ValidationError if the policy is not publishable.
func (s *Service) Publish(ctx context.Context, orgID, id, author string) (*Version, error) {
	p, err := s.store.GetPolicy(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if err := Validate(p.OrgID, p.Name, p.Agents, p.Rules); err != nil {
		return nil, err
	}

	msg, err := CanonicalMessage(p.ID, p.OrgID, p.Name, p.Agents, p.Rules)
	if err != nil {
		return nil, err
	}
	hash, err := ContentHash(p.ID, p.OrgID, p.Name, p.Agents, p.Rules)
	if err != nil {
		return nil, err
	}

	// Idempotent republish: identical content already versioned → reuse it (keeping
	// its original signature and publish metadata), just re-designate it active.
	if existing, gerr := s.store.GetVersion(ctx, orgID, id, hash); gerr == nil {
		if aerr := s.setActive(ctx, p, existing.VersionHash); aerr != nil {
			return nil, aerr
		}
		return existing, nil
	} else if !errors.Is(gerr, ErrVersionNotFound) {
		return nil, gerr
	}

	v := &Version{
		VersionHash: hash,
		PolicyID:    p.ID,
		OrgID:       p.OrgID,
		Name:        p.Name,
		Agents:      nonNilStrings(p.Agents),
		Rules:       nonNilRules(p.Rules),
		Signature:   s.signer.SignDetached(Canonicalization, msg),
		Author:      author,
		ParentHash:  p.ActiveVersionHash, // the version this one supersedes ("" if first)
		PublishedAt: s.now(),
	}
	if _, err := s.store.PutVersion(ctx, v); err != nil {
		return nil, err
	}
	if err := s.setActive(ctx, p, hash); err != nil {
		return nil, err
	}
	return v, nil
}

// ListVersions returns a policy's immutable versions, newest first.
func (s *Service) ListVersions(ctx context.Context, orgID, id string) ([]*Version, error) {
	if _, err := s.store.GetPolicy(ctx, orgID, id); err != nil {
		return nil, err
	}
	return s.store.ListVersions(ctx, orgID, id)
}

// Active returns the version a policy currently designates as serving, or
// ErrVersionNotFound if the policy has never been published.
func (s *Service) Active(ctx context.Context, orgID, id string) (*Version, error) {
	p, err := s.store.GetPolicy(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if p.ActiveVersionHash == "" {
		return nil, ErrVersionNotFound
	}
	return s.store.GetVersion(ctx, orgID, id, p.ActiveVersionHash)
}

// Rollback restores a prior version by re-designating it active and resetting the
// working copy to its content (TRD §6: "rollback = republish a prior hash"). Because
// versions are content-addressed and immutable, no new version row is created — the
// prior signed version is reinstated exactly. The target must be a version of this
// policy.
func (s *Service) Rollback(ctx context.Context, orgID, id, versionHash string) (*Version, error) {
	p, err := s.store.GetPolicy(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	target, err := s.store.GetVersion(ctx, orgID, id, versionHash)
	if err != nil {
		return nil, err
	}
	// Restore the working copy to the target version's content so a subsequent edit
	// starts from the rolled-back state, and re-point active.
	p.Name = target.Name
	p.Agents = target.Agents
	p.Rules = target.Rules
	p.Status = StatusPublished
	p.ActiveVersionHash = target.VersionHash
	p.UpdatedAt = s.now()
	if err := s.store.UpdatePolicy(ctx, p); err != nil {
		return nil, err
	}
	return target, nil
}

// setActive marks the working copy published and pointing at hash.
func (s *Service) setActive(ctx context.Context, p *Policy, hash string) error {
	p.Status = StatusPublished
	p.ActiveVersionHash = hash
	p.UpdatedAt = s.now()
	return s.store.UpdatePolicy(ctx, p)
}

// VerifyVersion re-derives a version's canonical bytes and checks its Ed25519
// signature against pub — the standalone verification a third party (auditor,
// regulator) runs with just the version and the published public key.
func VerifyVersion(v *Version, pub ed25519.PublicKey) error {
	if v.Signature.Canonicalization != Canonicalization {
		return fmt.Errorf("policyctl: unsupported canonicalization %q", v.Signature.Canonicalization)
	}
	msg, err := CanonicalMessage(v.PolicyID, v.OrgID, v.Name, v.Agents, v.Rules)
	if err != nil {
		return err
	}
	return signing.VerifyDetached(pub, msg, v.Signature)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilRules(r []Rule) []Rule {
	if r == nil {
		return []Rule{}
	}
	return r
}

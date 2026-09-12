package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/trust-infra/authorize-svc/internal/policyctl"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// This file is the control-plane HTTP surface (ROADMAP Task 2.2): CRUD + publish +
// versions + rollback + the org's active bundle, over /v1/policies. Handlers are thin
// wrappers over policyctl.Service (Task 2.1) — no policy logic lives here.
//
// Boundary note (TRD §3, A2#2): these endpoints share this binary with the decision
// plane for MVP, but they are the CONTROL plane. The hot path never calls them; a
// publish/rollback here invalidates the decision plane's cached bundle for the org
// (immediate same-process convergence). At Phase 5 this surface splits into policy-svc.

// maxPolicyBodyBytes caps a control-plane request body.
const maxPolicyBodyBytes = 256 << 10 // 256 KiB

// policyBundleInvalidator is the hook the publish/rollback handlers call to force the
// decision plane to converge immediately (internal/bundle.Provider.Invalidate).
type policyBundleInvalidator interface {
	Invalidate(ctx context.Context, orgID string) error
}

// policySimulator dry-runs a policy version against a batch of requests, returning the
// version label evaluated and one would-be (unsigned, shadow) decision per request
// (internal/bundle.Simulator). Task 2.3.
type policySimulator interface {
	Simulate(ctx context.Context, orgID, policyID, versionHash string, reqs []contractsv1.AuthorizeRequest) (string, []contractsv1.Decision, error)
}

// WithControlPlane wires the policy control-plane endpoints (Task 2.2/2.3). svc is the
// authoring/publish service; invalidator (optional) forces immediate bundle
// convergence after a same-process publish/rollback; sim (optional) backs
// POST /v1/policies/{id}/simulate.
func (s *Server) WithControlPlane(svc *policyctl.Service, invalidator policyBundleInvalidator, sim policySimulator) *Server {
	s.policySvc = svc
	s.bundleInvalidator = invalidator
	s.simulator = sim
	return s
}

// --- request/response DTOs ---------------------------------------------------

type policyWriteRequest struct {
	Name   string           `json:"name"`
	Agents []string         `json:"agents"`
	Rules  []policyctl.Rule `json:"rules"`
}

type publishRequest struct {
	Author string `json:"author"`
}

type rollbackRequest struct {
	VersionHash string `json:"version_hash"`
}

// maxSimulateRequests caps a dry-run batch so a simulate call cannot be used to burn
// unbounded CPU.
const maxSimulateRequests = 500

type simulateRequest struct {
	// VersionHash selects a published version to dry-run; empty means the current
	// working copy (draft).
	VersionHash string                          `json:"version_hash"`
	Requests    []contractsv1.AuthorizeRequest `json:"requests"`
}

type simulateResponse struct {
	VersionHash string                   `json:"version_hash"` // the version label evaluated
	Shadow      bool                     `json:"shadow"`       // always true: results are advisory
	Results     []contractsv1.Decision   `json:"results"`
}

type policyListResponse struct {
	Data []*policyctl.Policy `json:"data"`
}

type versionListResponse struct {
	Data []*policyctl.Version `json:"data"`
}

// --- collection: /v1/policies ------------------------------------------------

// handlePolicies dispatches the collection endpoint by method: POST creates a draft,
// GET is reserved (listing across an org needs a store index added later) → 405 for now
// on anything but POST.
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.handleCreatePolicy(w, r)
	default:
		w.Header().Set("Allow", http.MethodPost)
		s.writeProblem(w, r, http.StatusMethodNotAllowed, codeMethodNotAllowed,
			"Method not allowed", "This endpoint supports POST (create policy).", nil)
	}
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	var body policyWriteRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	p, err := s.policySvc.Create(r.Context(), org, body.Name, body.Agents, body.Rules)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// --- item: /v1/policies/{id} -------------------------------------------------

func (s *Server) handlePolicyItem(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleGetPolicy(w, r)
	case http.MethodPut:
		s.handleUpdatePolicy(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		s.writeProblem(w, r, http.StatusMethodNotAllowed, codeMethodNotAllowed,
			"Method not allowed", "This endpoint supports GET and PUT.", nil)
	}
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	p, err := s.policySvc.Get(r.Context(), org, r.PathValue("id"))
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	var body policyWriteRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	p, err := s.policySvc.Update(r.Context(), org, r.PathValue("id"), body.Name, body.Agents, body.Rules)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// --- publish / rollback / versions -------------------------------------------

func (s *Server) handlePublishPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	// author is optional; default to the authenticated key id for provenance.
	body := publishRequest{}
	_ = s.decodeOptionalBody(r, &body)
	if body.Author == "" {
		if p, ok := principalOf(r); ok {
			body.Author = p.KeyID
		}
	}

	id := r.PathValue("id")
	v, err := s.policySvc.Publish(r.Context(), org, id, body.Author)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	s.invalidateBundle(r, org)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleRollbackPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	var body rollbackRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	if body.VersionHash == "" {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "version_hash is required.", nil)
		return
	}
	v, err := s.policySvc.Rollback(r.Context(), org, r.PathValue("id"), body.VersionHash)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	s.invalidateBundle(r, org)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	versions, err := s.policySvc.ListVersions(r.Context(), org, r.PathValue("id"))
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, versionListResponse{Data: versions})
}

// --- simulate: /v1/policies/{id}/simulate ------------------------------------

// handleSimulate dry-runs a policy version (or the working-copy draft) against a batch
// of supplied requests and returns the would-be verdicts, without signing or auditing
// anything (ROADMAP Task 2.3). Every result is marked shadow — a simulation is never
// enforceable.
func (s *Server) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	if s.simulator == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Simulation unavailable", "Policy simulation is not enabled on this instance.", nil)
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	var body simulateRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	if len(body.Requests) == 0 {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "requests must contain at least one authorize request.", nil)
		return
	}
	if len(body.Requests) > maxSimulateRequests {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "too many requests in one simulation batch.", nil)
		return
	}
	// Validate each request's wire shape (the same guard /v1/authorize applies), so a
	// simulation reflects real inputs. evaluated_at is allowed here (replaying history).
	for i, req := range body.Requests {
		if items := validateAuthorizeRequest(req); len(items) > 0 {
			s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
				"Validation failed", fmt.Sprintf("requests[%d] is invalid.", i), items)
			return
		}
	}

	label, results, err := s.simulator.Simulate(r.Context(), org, r.PathValue("id"), body.VersionHash, body.Requests)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, simulateResponse{VersionHash: label, Shadow: true, Results: results})
}

// --- active bundle: /v1/policies/active --------------------------------------

// handleActiveBundle returns the version the org's decision plane is currently serving
// (ROADMAP A#4 — "a customer sees which version is serving"). It reads control-plane
// state (the source of truth), so it reflects a publish immediately, while the decision
// plane converges within the refresh window.
func (s *Server) handleActiveBundle(w http.ResponseWriter, r *http.Request) {
	if !s.controlPlaneReady(w, r) {
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	ref, err := s.policySvc.ActiveBundle(r.Context(), org)
	if err != nil {
		s.writePolicyError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ref)
}

// --- helpers -----------------------------------------------------------------

func (s *Server) controlPlaneReady(w http.ResponseWriter, r *http.Request) bool {
	if s.policySvc == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Control plane unavailable", "Policy authoring is not enabled on this instance.", nil)
		return false
	}
	return true
}

func (s *Server) orgOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := principalOf(r)
	if !ok {
		s.writeProblem(w, r, http.StatusInternalServerError, codeInternal,
			"Internal server error", "Authentication context was not present.", nil)
		return "", false
	}
	return p.OrgID, true
}

// decodePolicyBody reads a required JSON body with unknown-field rejection.
func (s *Server) decodePolicyBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeProblem(w, r, http.StatusRequestEntityTooLarge, codeValidationFailed,
				"Request too large", "The request body exceeds the maximum allowed size.", nil)
			return false
		}
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Malformed request body", jsonErrorDetail(err), nil)
		return false
	}
	return true
}

// decodeOptionalBody reads an optional JSON body (empty body is fine).
func (s *Server) decodeOptionalBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxPolicyBodyBytes))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) invalidateBundle(r *http.Request, orgID string) {
	if s.bundleInvalidator == nil {
		return
	}
	if err := s.bundleInvalidator.Invalidate(r.Context(), orgID); err != nil {
		reqLogger(r).Warn("bundle invalidate failed; convergence will wait for the refresh window", "org", orgID, "err", err)
	}
}

// writePolicyError maps a policyctl error to the right RFC 7807 response. A
// ValidationError becomes a 422 with field-level items.
func (s *Server) writePolicyError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *policyctl.ValidationError
	if errors.As(err, &ve) {
		items := make([]contractsv1.ValidationItem, 0, len(ve.Problems))
		for _, p := range ve.Problems {
			items = append(items, contractsv1.ValidationItem{Pointer: p.Pointer, Detail: p.Detail})
		}
		s.writeProblem(w, r, http.StatusUnprocessableEntity, codeValidationFailed,
			"Policy validation failed", "The policy is not publishable; see errors.", items)
		return
	}
	switch {
	case errors.Is(err, policyctl.ErrPolicyNotFound), errors.Is(err, policyctl.ErrVersionNotFound), errors.Is(err, policyctl.ErrBundleNotFound):
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Not found", "No such policy, version, or active bundle for this org.", nil)
	case errors.Is(err, policyctl.ErrPolicyExists):
		s.writeProblem(w, r, http.StatusConflict, codeConflict,
			"Conflict", "A policy with that id already exists.", nil)
	default:
		reqLogger(r).Error("control-plane operation failed", "err", err)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Control plane error", "The policy operation could not be completed.", nil)
	}
}

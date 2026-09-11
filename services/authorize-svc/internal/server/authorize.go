package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// maxBodyBytes caps the authorize request body (TRD §11: reject oversized bodies).
const maxBodyBytes = 64 << 10 // 64 KiB

// Contract-mirrored validators for the fields this thin layer checks. Deep policy
// semantics are the engine's job; here we only guard the wire shape.
var (
	reMoney        = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	reCurrency     = regexp.MustCompile(`^[A-Z]{3}$`)
	reJurisdiction = regexp.MustCompile(`^[A-Z]{2}$`)
)

var validTargetTypes = map[contractsv1.TargetType]bool{
	contractsv1.TargetVendor:   true,
	contractsv1.TargetAccount:  true,
	contractsv1.TargetAddress:  true,
	contractsv1.TargetInternal: true,
	contractsv1.TargetUnknown:  true,
}

// handleAuthorize decodes and validates the request, then delegates to the
// Authorizer seam and writes the signed Decision. Thin by design.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req contractsv1.AuthorizeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // contract sets additionalProperties:false
	if err := dec.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeProblem(w, r, http.StatusRequestEntityTooLarge, codeValidationFailed,
				"Request too large", "The request body exceeds the maximum allowed size.", nil)
			return
		}
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Malformed request body", jsonErrorDetail(err), nil)
		return
	}
	// Exactly one JSON value is expected.
	if dec.More() {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Malformed request body", "Body must contain a single JSON object.", nil)
		return
	}

	if items := validateAuthorizeRequest(req); len(items) > 0 {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "One or more fields are invalid.", items)
		return
	}

	// Clients must not set orchestrator-injected fields; the service owns them.
	// Stamp evaluated_at authoritatively (the engine echoes it onto the Decision).
	req.EvaluatedAt = ""

	// Idempotency (Task 1.7): a repeated key returns the already-issued decision, so
	// a client retry never produces a second, divergent one. Best-effort — a lookup
	// miss or error falls through to a fresh evaluation.
	if dec, ok := s.idempotentReplay(r, req); ok {
		w.Header().Set("X-Decision-Id", dec.DecisionID)
		w.Header().Set("X-Idempotent-Replay", "true")
		writeJSON(w, http.StatusOK, dec)
		return
	}

	decision, err := s.authz.Authorize(r.Context(), req)
	if err != nil {
		reqLogger(r).Error("authorize failed", "err", err)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Decision unavailable", "The decision plane could not produce a decision.", nil)
		return
	}

	// Record the decision under its idempotency key BEFORE responding, so a retry
	// that races the client's receipt still resolves to this decision.
	s.saveIdempotent(r, req, decision)

	w.Header().Set("X-Decision-Id", decision.DecisionID)
	writeJSON(w, http.StatusOK, decision)

	// Persist to the append-only audit log AFTER the response is written, so the
	// write never adds to latency_ms (TRD §14). Enqueue hands off to the async
	// writer; the DB round-trip happens on a background goroutine.
	s.enqueueAudit(r, req, decision)
}

// idempotentReplay returns a previously-issued decision for this request's
// idempotency key, if one is cached. No-op (ok=false) when idempotency is not wired
// or the lookup errors — the cache must never block a decision.
func (s *Server) idempotentReplay(r *http.Request, req contractsv1.AuthorizeRequest) (contractsv1.Decision, bool) {
	if s.idem == nil || req.IdempotencyKey == "" {
		return contractsv1.Decision{}, false
	}
	principal, ok := principalOf(r)
	if !ok {
		return contractsv1.Decision{}, false
	}
	dec, hit, err := s.idem.Lookup(r.Context(), principal.OrgID, req.IdempotencyKey)
	if err != nil {
		reqLogger(r).Warn("idempotency lookup failed; evaluating fresh", "err", err)
		return contractsv1.Decision{}, false
	}
	return dec, hit
}

// saveIdempotent caches the freshly-issued decision under its idempotency key.
// Best-effort: a store error is logged and does not fail the request.
func (s *Server) saveIdempotent(r *http.Request, req contractsv1.AuthorizeRequest, decision contractsv1.Decision) {
	if s.idem == nil || req.IdempotencyKey == "" {
		return
	}
	principal, ok := principalOf(r)
	if !ok {
		return
	}
	if err := s.idem.Save(r.Context(), principal.OrgID, req.IdempotencyKey, decision); err != nil {
		reqLogger(r).Warn("idempotency save failed", "err", err)
	}
}

// enqueueAudit builds the audit record from the authenticated caller + request +
// decision and hands it to the async writer. No-op when audit is not wired.
func (s *Server) enqueueAudit(r *http.Request, req contractsv1.AuthorizeRequest, decision contractsv1.Decision) {
	if s.auditWriter == nil {
		return
	}
	principal, ok := principalOf(r)
	if !ok {
		reqLogger(r).Error("audit skipped: no principal on authenticated request")
		return
	}
	rec := audit.RecordFromDecision(principal.OrgID, principal.KeyID, req, decision)
	if s.retentionFor != nil {
		rec.RetainUntil = time.Now().UTC().Add(s.retentionFor(principal.Tier))
	}
	s.auditWriter.Enqueue(rec)
}

// validateAuthorizeRequest checks the required fields and their shapes against the
// frozen contract, returning field-level problems (JSON Pointers) for a 7807 body.
func validateAuthorizeRequest(req contractsv1.AuthorizeRequest) []contractsv1.ValidationItem {
	var items []contractsv1.ValidationItem
	add := func(pointer, detail string) {
		items = append(items, contractsv1.ValidationItem{Pointer: pointer, Detail: detail})
	}

	if l := len(req.AgentID); l < 1 || l > 256 {
		add("/agent_id", "must be 1..256 characters")
	}
	if l := len(req.Action); l < 1 || l > 128 {
		add("/action", "must be 1..128 characters")
	}
	if !reMoney.MatchString(req.Amount) {
		add("/amount", `must be a canonical decimal string matching ^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	}
	if !reCurrency.MatchString(req.Currency) {
		add("/currency", "must be a 3-letter uppercase ISO 4217 code")
	}
	if req.Target.Type == "" || !validTargetTypes[req.Target.Type] {
		add("/target/type", "must be one of vendor|account|address|internal|unknown")
	}
	if l := len(req.Target.ID); l < 1 || l > 256 {
		add("/target/id", "must be 1..256 characters")
	}
	if req.Jurisdiction != "" && !reJurisdiction.MatchString(req.Jurisdiction) {
		add("/jurisdiction", "must be a 2-letter uppercase ISO 3166-1 alpha-2 code")
	}
	if l := len(req.IdempotencyKey); l < 8 || l > 128 {
		add("/idempotency_key", "must be 8..128 characters")
	}
	return items
}

// jsonErrorDetail returns a caller-safe explanation of a decode failure. It never
// leaks internals beyond the standard library's own message.
func jsonErrorDetail(err error) string {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return "Invalid JSON syntax."
	}
	var typ *json.UnmarshalTypeError
	if errors.As(err, &typ) {
		return "Field " + typ.Field + " has the wrong type."
	}
	if errors.Is(err, io.EOF) {
		return "Request body is empty."
	}
	// DisallowUnknownFields and other decode errors: pass the std message; it is
	// developer-safe (field name only, no secrets).
	return err.Error()
}

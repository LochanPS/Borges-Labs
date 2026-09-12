package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/trust-infra/authorize-svc/internal/hold"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// This file is the two-phase budget lifecycle over HTTP (ROADMAP A#2, Task 3.1):
//   - a budget-affecting APPROVE places a hold (see placeHold, called from the authorize
//     handler after the response decision is fixed);
//   - POST /v1/authorize/{id}/capture  commits it (payment succeeded);
//   - POST /v1/authorize/{id}/void     releases it (payment failed/aborted).
// Both are idempotent and org-scoped. The hold is addressed by the decision id.

// WithHolds wires the budget-hold store (Task 3.1). When set, the authorize handler
// places a hold for a budget-affecting APPROVE and the capture/void endpoints are live.
func (s *Server) WithHolds(store hold.Store) *Server {
	s.holds = store
	return s
}

// holdResponse is the capture/void + hold-read body.
type holdResponse struct {
	DecisionID string     `json:"decision_id"`
	State      hold.State `json:"state"`
	BudgetID   string     `json:"budget_id,omitempty"`
	Amount     string     `json:"amount,omitempty"`
	Currency   string     `json:"currency,omitempty"`
	ExpiresAt  string     `json:"expires_at,omitempty"`
}

func toHoldResponse(h *hold.Hold) holdResponse {
	r := holdResponse{
		DecisionID: h.DecisionID,
		State:      h.State,
		BudgetID:   h.BudgetID,
		Amount:     h.Amount,
		Currency:   h.Currency,
	}
	if !h.ExpiresAt.IsZero() {
		r.ExpiresAt = h.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return r
}

// placeHold records the reservation for a budget-affecting APPROVE. It is called on the
// FRESH decision path (not on an idempotent replay — the hold already exists then).
// Best-effort logging on error: Place is idempotent, and a missing hold surfaces later
// as a 404 on capture/void rather than corrupting a decision that was already returned.
func (s *Server) placeHold(r *http.Request, req contractsv1.AuthorizeRequest, dec contractsv1.Decision, orgID string) {
	if s.holds == nil {
		return
	}
	ob, ok := findObligation(dec.Obligations, contractsv1.ObligationCaptureWithin)
	if !ok {
		return
	}
	h := &hold.Hold{
		DecisionID: dec.DecisionID,
		OrgID:      orgID,
		AgentID:    req.AgentID,
		BudgetID:   stringParam(ob.Params, "budget_id"),
		Amount:     req.Amount,
		Currency:   req.Currency,
		State:      hold.StateHeld,
		ExpiresAt:  parseParamTime(ob.Params, "expires_at"),
	}
	if err := s.holds.Place(r.Context(), h); err != nil {
		reqLogger(r).Error("hold place failed", "err", err, "decision_id", dec.DecisionID)
	}
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	s.transitionHold(w, r, hold.Store.Capture)
}

func (s *Server) handleVoid(w http.ResponseWriter, r *http.Request) {
	s.transitionHold(w, r, hold.Store.Void)
}

// transitionHold is the shared capture/void handler: authenticate → org-scope → apply
// the transition → map the result. fn is Store.Capture or Store.Void.
func (s *Server) transitionHold(w http.ResponseWriter, r *http.Request, fn func(hold.Store, context.Context, string, string) (*hold.Hold, error)) {
	if s.holds == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Holds unavailable", "Two-phase budget holds are not enabled on this instance.", nil)
		return
	}
	principal, ok := principalOf(r)
	if !ok {
		s.writeProblem(w, r, http.StatusInternalServerError, codeInternal,
			"Internal server error", "Authentication context was not present.", nil)
		return
	}
	id := r.PathValue("id")
	if !reULID.MatchString(id) {
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Hold not found", "No hold matches the given decision id.", nil)
		return
	}

	h, err := fn(s.holds, r.Context(), principal.OrgID, id)
	if err != nil {
		s.writeHoldError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toHoldResponse(h))
}

func (s *Server) writeHoldError(w http.ResponseWriter, r *http.Request, err error) {
	var ce *hold.ConflictError
	switch {
	case errors.Is(err, hold.ErrNotFound):
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Hold not found", "No hold matches the given decision id (it may have expired).", nil)
	case errors.As(err, &ce):
		s.writeProblem(w, r, http.StatusConflict, codeConflict,
			"Hold state conflict", ce.Reason, nil)
	default:
		reqLogger(r).Error("hold transition failed", "err", err)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Hold operation failed", "The hold could not be updated.", nil)
	}
}

// --- helpers -----------------------------------------------------------------

func findObligation(obs []contractsv1.Obligation, typ string) (contractsv1.Obligation, bool) {
	for _, o := range obs {
		if o.Type == typ {
			return o, true
		}
	}
	return contractsv1.Obligation{}, false
}

func stringParam(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func parseParamTime(m map[string]interface{}, k string) time.Time {
	if t, err := time.Parse(time.RFC3339, stringParam(m, k)); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

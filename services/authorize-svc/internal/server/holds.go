package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/trust-infra/authorize-svc/internal/hold"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// findObligation returns the first obligation of the given type, if present.
func findObligation(obs []contractsv1.Obligation, typ string) (contractsv1.Obligation, bool) {
	for _, o := range obs {
		if o.Type == typ {
			return o, true
		}
	}
	return contractsv1.Obligation{}, false
}

// This file is the two-phase budget lifecycle over HTTP (ROADMAP A#2, Task 3.1/3.2):
//   - a budget-affecting APPROVE reserves against the budget counter and records a hold
//     during evaluation (see internal/budget.Reserver, wired into the engine);
//   - POST /v1/authorize/{id}/capture  commits it (payment succeeded);
//   - POST /v1/authorize/{id}/void     releases it (payment failed/aborted; counter is
//     decremented).
// Both are idempotent and org-scoped; the hold is addressed by the decision id.

// budgetLifecycle is the capture/void surface the reserver provides (Phase 3.2).
// *budget.Reserver satisfies it. Capture commits (counter unchanged); Void releases and
// decrements the counter exactly once.
type budgetLifecycle interface {
	Capture(ctx context.Context, orgID, decisionID string) (*hold.Hold, error)
	Void(ctx context.Context, orgID, decisionID string) (*hold.Hold, error)
}

// WithBudget wires the budget reserver's capture/void lifecycle (Task 3.2). When set,
// the capture/void endpoints are live. The same reserver is wired into the engine
// (Engine.WithReserver) so reservations placed during authorize are what these settle.
func (s *Server) WithBudget(lifecycle budgetLifecycle) *Server {
	s.budget = lifecycle
	return s
}

// holdResponse is the capture/void body.
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

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	s.transitionHold(w, r, budgetLifecycle.Capture)
}

func (s *Server) handleVoid(w http.ResponseWriter, r *http.Request) {
	s.transitionHold(w, r, budgetLifecycle.Void)
}

// transitionHold is the shared capture/void handler: authenticate → org-scope → apply
// the transition → map the result. fn is budgetLifecycle.Capture or .Void.
func (s *Server) transitionHold(w http.ResponseWriter, r *http.Request, fn func(budgetLifecycle, context.Context, string, string) (*hold.Hold, error)) {
	if s.budget == nil {
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

	h, err := fn(s.budget, r.Context(), principal.OrgID, id)
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

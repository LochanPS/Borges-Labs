package server

import (
	"context"
	"net/http"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
)

// This file is the API-key management surface (control plane): create, list, revoke
// keys over /v1/keys. It is authenticated + org-scoped like the other control-plane
// endpoints. The raw secret is returned exactly once, on create; only its hash is
// ever stored. Revocation evicts the key cache so "revoke = immediate" holds (TRD §11).
//
// Not the hot path: the decision plane authenticates via KeyStore.LookupByID; this
// surface uses the separate auth.KeyAdmin seam so management never touches that read.

// keyCacheInvalidate drops a key from the hot-path cache immediately (RedisKeyCache.
// Invalidate). Optional: nil in tests / cache-less deployments.
type keyCacheInvalidate func(ctx context.Context, keyID string) error

// WithKeyAdmin wires the /v1/keys management endpoints. admin persists/lists/revokes
// keys; invalidate (optional) evicts the hot-path cache on revoke.
func (s *Server) WithKeyAdmin(admin auth.KeyAdmin, invalidate keyCacheInvalidate) *Server {
	s.keyAdmin = admin
	s.keyCacheInvalidate = invalidate
	return s
}

// --- DTOs --------------------------------------------------------------------

type createKeyRequest struct {
	Env    string `json:"env"`    // "live" | "test"
	Tier   string `json:"tier"`   // optional; defaults to "default"
	Shadow *bool  `json:"shadow"` // optional; defaults to true (advisory-first, A#5)
}

// apiKeyView is the non-secret representation returned to the dashboard.
type apiKeyView struct {
	ID        string     `json:"id"`
	Prefix    string     `json:"prefix"`
	OrgID     string     `json:"org_id"`
	Env       string     `json:"env"`
	Tier      string     `json:"tier"`
	IsActive  bool       `json:"is_active"`
	Shadow    bool       `json:"shadow"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// createdApiKeyView is apiKeyView plus the one-time plaintext secret.
type createdApiKeyView struct {
	apiKeyView
	Secret string `json:"secret"`
}

type keyListResponse struct {
	Data []apiKeyView `json:"data"`
}

func prefixFor(env string) string {
	if env == auth.EnvTest {
		return "azn_test_"
	}
	return "azn_live_"
}

func viewOf(ki auth.KeyInfo) apiKeyView {
	return apiKeyView{
		ID:        ki.KeyID,
		Prefix:    prefixFor(ki.Env),
		OrgID:     ki.OrgID,
		Env:       ki.Env,
		Tier:      ki.Tier,
		IsActive:  ki.Status == auth.StatusActive,
		Shadow:    ki.Shadow,
		CreatedAt: ki.CreatedAt,
		RevokedAt: ki.RevokedAt,
	}
}

// --- handlers ----------------------------------------------------------------

func (s *Server) keyAdminReady(w http.ResponseWriter, r *http.Request) bool {
	if s.keyAdmin == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Key management unavailable", "API-key management is not enabled on this instance.", nil)
		return false
	}
	return true
}

// handleKeys dispatches the collection endpoint: GET lists, POST creates.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if !s.keyAdminReady(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleListKeys(w, r)
	case http.MethodPost:
		s.handleCreateKey(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		s.writeProblem(w, r, http.StatusMethodNotAllowed, codeMethodNotAllowed,
			"Method not allowed", "This endpoint supports GET (list) and POST (create key).", nil)
	}
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	keys, err := s.keyAdmin.ListKeys(r.Context(), org)
	if err != nil {
		reqLogger(r).Error("list keys failed", "err", err)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Key management error", "Could not list keys.", nil)
		return
	}
	views := make([]apiKeyView, 0, len(keys))
	for _, k := range keys {
		views = append(views, viewOf(k))
	}
	writeJSON(w, http.StatusOK, keyListResponse{Data: views})
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	var body createKeyRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	if body.Env != auth.EnvLive && body.Env != auth.EnvTest {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "env must be \"live\" or \"test\".", nil)
		return
	}
	tier := body.Tier
	if tier == "" {
		tier = "default"
	}

	gk, err := auth.NewKey(body.Env, org, tier)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed, "Validation failed", err.Error(), nil)
		return
	}
	if body.Shadow != nil {
		gk.Record.Shadow = *body.Shadow
	}

	now := time.Now().UTC()
	if err := s.keyAdmin.CreateKey(r.Context(), gk.Record, now); err != nil {
		reqLogger(r).Error("create key failed", "err", err, "org", org)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Key management error", "Could not create the key.", nil)
		return
	}

	view := createdApiKeyView{
		apiKeyView: viewOf(auth.KeyInfo{
			KeyID: gk.Record.KeyID, OrgID: org, Tier: tier, Env: gk.Record.Env,
			Status: gk.Record.Status, Shadow: gk.Record.Shadow, CreatedAt: now,
		}),
		Secret: gk.Plaintext, // shown ONCE; never retrievable again
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if !s.keyAdminReady(w, r) {
		return
	}
	org, ok := s.orgOf(w, r)
	if !ok {
		return
	}
	keyID := r.PathValue("id")
	info, err := s.keyAdmin.RevokeKey(r.Context(), org, keyID, time.Now().UTC())
	if err != nil {
		if err == auth.ErrKeyNotFound {
			s.writeProblem(w, r, http.StatusNotFound, codeNotFound, "Not found", "No such key for this org.", nil)
			return
		}
		reqLogger(r).Error("revoke key failed", "err", err, "org", org)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Key management error", "Could not revoke the key.", nil)
		return
	}
	// Evict the hot-path cache so the revocation takes effect immediately (TRD §11).
	if s.keyCacheInvalidate != nil {
		if err := s.keyCacheInvalidate(r.Context(), keyID); err != nil {
			reqLogger(r).Warn("key cache invalidate failed; revocation waits out the TTL", "key_id", keyID, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, viewOf(info))
}

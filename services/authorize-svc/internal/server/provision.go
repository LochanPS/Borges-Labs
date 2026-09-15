package server

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
)

// Org onboarding / bootstrap (M1). A brand-new org has no API key yet, so it cannot
// call POST /v1/keys (which requires an existing org key). POST /v1/provision/keys
// solves that chicken-and-egg: it mints an org's FIRST key, authorized by a
// PLATFORM-level shared secret (X-Provision-Token) rather than an org key.
//
// This is a privileged control-surface endpoint. Only a trusted server (e.g. the
// dashboard backend that creates orgs) should hold the token; never expose it to a
// browser. It is mounted only when AUTHZ_PROVISION_TOKEN is set.

// WithProvisioning enables POST /v1/provision/keys, authorized by token. Empty token
// leaves the endpoint unmounted. Requires a KeyAdmin (WithKeyAdmin) to persist keys.
func (s *Server) WithProvisioning(token string) *Server {
	s.provisionToken = token
	return s
}

type provisionKeyRequest struct {
	OrgID  string `json:"org_id"`
	Env    string `json:"env"`    // "live" | "test"
	Tier   string `json:"tier"`   // optional; defaults to "default"
	Shadow *bool  `json:"shadow"` // optional; defaults to true (advisory-first)
}

func (s *Server) handleProvisionKey(w http.ResponseWriter, r *http.Request) {
	// Constant-time platform-token check. A missing/wrong token is 401 and reveals
	// nothing about org state.
	presented := r.Header.Get("X-Provision-Token")
	if s.provisionToken == "" ||
		subtle.ConstantTimeCompare([]byte(presented), []byte(s.provisionToken)) != 1 {
		s.writeProblem(w, r, http.StatusUnauthorized, codeUnauthorized,
			"Unauthorized", "A valid X-Provision-Token is required.", nil)
		return
	}
	if s.keyAdmin == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Provisioning unavailable", "Key management is not enabled on this instance.", nil)
		return
	}

	var body provisionKeyRequest
	if !s.decodePolicyBody(w, r, &body) {
		return
	}
	if body.OrgID == "" {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "org_id is required.", nil)
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

	gk, err := auth.NewKey(body.Env, body.OrgID, tier)
	if err != nil {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed, "Validation failed", err.Error(), nil)
		return
	}
	if body.Shadow != nil {
		gk.Record.Shadow = *body.Shadow
	}

	now := time.Now().UTC()
	if err := s.keyAdmin.CreateKey(r.Context(), gk.Record, now); err != nil {
		reqLogger(r).Error("provision key failed", "err", err, "org", body.OrgID)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Provisioning error", "Could not create the org key.", nil)
		return
	}
	reqLogger(r).Info("org provisioned", "org", body.OrgID, "env", body.Env, "key_id", gk.Record.KeyID)

	view := createdApiKeyView{
		apiKeyView: viewOf(auth.KeyInfo{
			KeyID: gk.Record.KeyID, OrgID: body.OrgID, Tier: tier, Env: gk.Record.Env,
			Status: gk.Record.Status, Shadow: gk.Record.Shadow, CreatedAt: now,
		}),
		Secret: gk.Plaintext, // shown ONCE
	}
	writeJSON(w, http.StatusCreated, view)
}

package server

import "net/http"

// handleKeysPublic serves the JWKS-style public key set used to verify decision
// signatures (Task 1.5, docs/decision-canonicalization.md §3). It is public and
// unauthenticated by design: anyone must be able to verify a decision receipt.
//
// The response is cacheable; keys rotate slowly and retiring keys stay published.
func (s *Server) handleKeysPublic(w http.ResponseWriter, r *http.Request) {
	if s.keysJWKS == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Keys unavailable", "Decision signing keys are not configured.", nil)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.keysJWKS())
}

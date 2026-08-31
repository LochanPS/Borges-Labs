package server

import (
	"net/http"
	"regexp"
)

// reULID mirrors the frozen contract's ULID pattern (common.schema.json).
var reULID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// handleGetDecision is a stub for GET /v1/decisions/{id}. There is no audit store
// yet, so a well-formed id resolves to 404 (no such record) and a malformed id is
// likewise "not found" — both within the endpoint's declared responses. The read
// path (record_hash, signature_verified) lands with the store.
func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !reULID.MatchString(id) {
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Decision not found", "No decision matches the given id.", nil)
		return
	}
	// Store not implemented yet — nothing is persisted, so nothing is found.
	s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
		"Decision not found", "No decision matches the given id.", nil)
}

// handleNotFound is the catch-all: any unrouted path is a 7807 404.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
		"Not found", "The requested resource does not exist.", nil)
}

package server

import (
	"encoding/json"
	"net/http"

	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// problemBaseURI is the dereferenceable root for problem `type` URIs. Appending a
// stable machine code yields the documented type for that error class.
const problemBaseURI = "https://contracts.trust-infra.dev/v1/errors/"

// Stable machine-readable error codes (Problem.code) SDKs switch on.
const (
	codeValidationFailed = "validation_failed"
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeInternal         = "internal_error"
	codeUnauthorized     = "unauthorized"
	codeForbidden        = "forbidden"
	codeReplayDetected   = "replay_detected"
	codeAuthUnavailable  = "auth_unavailable"
	codeRateLimited      = "rate_limited"
)

// writeProblem emits an RFC 7807 problem+json response. `instance` is anchored to
// the request id so a specific occurrence is traceable to a log line.
func (s *Server) writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title, detail string, items []contractsv1.ValidationItem) {
	p := contractsv1.Problem{
		Type:     problemBaseURI + code,
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path + "#" + reqID(r),
		Code:     code,
		Errors:   items,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

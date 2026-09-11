package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// reULID mirrors the frozen contract's ULID pattern (common.schema.json).
var reULID = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// listPage is the GET /v1/decisions envelope (openapi listDecisions 200).
type listPage struct {
	Data       []contractsv1.Decision `json:"data"`
	NextCursor *string                `json:"next_cursor"`
}

// handleGetDecision fetches one stored decision for the authenticated caller's org
// and returns it with record_hash and a read-time signature_verified: true iff the
// Ed25519 signature validates AND the record_hash chain link is intact
// (decision.schema.json). A record from another org is "not found" — no cross-tenant
// read, and no oracle for existence.
func (s *Server) handleGetDecision(w http.ResponseWriter, r *http.Request) {
	if s.auditStore == nil {
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Decision not found", "No decision matches the given id.", nil)
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
		// Malformed id can never match a stored ULID — 404 within declared responses.
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Decision not found", "No decision matches the given id.", nil)
		return
	}

	rec, err := s.auditStore.Get(r.Context(), principal.OrgID, id)
	if errors.Is(err, audit.ErrNotFound) {
		s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
			"Decision not found", "No decision matches the given id.", nil)
		return
	}
	if err != nil {
		reqLogger(r).Error("audit get failed", "err", err, "decision_id", id)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Decision unavailable", "The decision record could not be read.", nil)
		return
	}

	writeJSON(w, http.StatusOK, rec.Decision(s.verifyRecord(rec)))
}

// handleListDecisions returns a paginated, filtered page of the org's decisions,
// newest first (openapi listDecisions). Filters: agent_id, verdict, from/to
// (evaluated_at bounds). Pagination is an opaque seq-based cursor.
func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	if s.auditStore == nil {
		writeJSON(w, http.StatusOK, listPage{Data: []contractsv1.Decision{}, NextCursor: nil})
		return
	}
	principal, ok := principalOf(r)
	if !ok {
		s.writeProblem(w, r, http.StatusInternalServerError, codeInternal,
			"Internal server error", "Authentication context was not present.", nil)
		return
	}

	f, items := parseListFilter(r)
	if len(items) > 0 {
		s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
			"Validation failed", "One or more query parameters are invalid.", items)
		return
	}

	page, err := s.auditStore.List(r.Context(), principal.OrgID, f)
	if err != nil {
		reqLogger(r).Error("audit list failed", "err", err)
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Decisions unavailable", "The decision records could not be read.", nil)
		return
	}

	out := listPage{Data: make([]contractsv1.Decision, 0, len(page.Records))}
	for _, rec := range page.Records {
		out.Data = append(out.Data, rec.Decision(s.verifyRecord(rec)))
	}
	if page.NextCursor > 0 {
		out.NextCursor = ptr(encodeCursor(page.NextCursor))
	}
	writeJSON(w, http.StatusOK, out)
}

// verifyRecord computes read-time signature_verified: the Ed25519 signature must
// validate AND the record_hash chain link must be intact. Either failing (a mutated
// row) yields false. Missing verifier => false (cannot attest).
func (s *Server) verifyRecord(rec *audit.Record) bool {
	if s.verifyDecision == nil {
		return false
	}
	sigOK := s.verifyDecision(rec.Decision(false)) == nil
	chainOK, err := audit.VerifyChainLink(rec)
	return sigOK && err == nil && chainOK
}

// parseListFilter reads the listing query params, returning field-level problems for
// anything malformed.
func parseListFilter(r *http.Request) (audit.Filter, []contractsv1.ValidationItem) {
	var items []contractsv1.ValidationItem
	add := func(pointer, detail string) {
		items = append(items, contractsv1.ValidationItem{Pointer: pointer, Detail: detail})
	}
	q := r.URL.Query()
	f := audit.Filter{
		AgentID: q.Get("agent_id"),
	}

	if v := q.Get("verdict"); v != "" {
		switch contractsv1.Verdict(v) {
		case contractsv1.VerdictApprove, contractsv1.VerdictDeny, contractsv1.VerdictReview:
			f.Verdict = contractsv1.Verdict(v)
		default:
			add("/verdict", "must be one of APPROVE|DENY|REVIEW")
		}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = t
		} else {
			add("/from", "must be an RFC 3339 date-time")
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = t
		} else {
			add("/to", "must be an RFC 3339 date-time")
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= audit.MaxListLimit {
			f.Limit = n
		} else {
			add("/limit", "must be an integer in 1..200")
		}
	}
	if v := q.Get("cursor"); v != "" {
		if c, err := decodeCursor(v); err == nil {
			f.Cursor = c
		} else {
			add("/cursor", "invalid pagination cursor")
		}
	}
	return f, items
}

// encodeCursor/decodeCursor make the seq-based cursor opaque to callers (base64 of
// the decimal seq). The exact encoding is an implementation detail behind the
// contract's "opaque pagination cursor".
func encodeCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(seq, 10)))
}

func decodeCursor(s string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(string(raw), 10, 64)
}

func ptr[T any](v T) *T { return &v }

// handleNotFound is the catch-all: any unrouted path is a 7807 404.
func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	s.writeProblem(w, r, http.StatusNotFound, codeNotFound,
		"Not found", "The requested resource does not exist.", nil)
}

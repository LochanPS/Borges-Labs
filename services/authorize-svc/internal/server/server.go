// Package server wires the HTTP surface for the decision plane.
//
// Scope (Phase 0): the /v1 decision-plane endpoints with thin handlers —
//   - POST /v1/authorize        evaluate a transaction (stub APPROVE for now)
//   - GET  /v1/health           liveness + dependency checks
//   - GET  /v1/decisions/{id}    fetch a stored decision (stub: not found)
//
// Handlers stay thin: decode/validate, delegate to the Authorizer seam, encode.
// Real policy evaluation lands behind the Authorizer interface in the engine
// package next. Errors are RFC 7807 (application/problem+json). Every request
// carries a generated request id, surfaced in logs and on the response.
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/trust-infra/authorize-svc/internal/audit"
	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/policyctl"
	"github.com/trust-infra/authorize-svc/internal/ratelimit"
	contractsv1 "github.com/trust-infra/contracts/gen/go/contractsv1"
)

// BuildInfo is stamped at build time via -ldflags (see Makefile).
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Check is a named liveness probe for a backing dependency.
type Check struct {
	Name string
	Ping func(context.Context) error
}

// Authorizer evaluates an authorization request into a signed Decision. The
// server depends only on this seam; the engine (stub today, real next) implements
// it. Keeping it an interface is what keeps the handler thin and swappable.
type Authorizer interface {
	Authorize(ctx context.Context, orgID string, req contractsv1.AuthorizeRequest, shadow bool) (contractsv1.Decision, error)
}

// Server holds handler dependencies.
type Server struct {
	log     *slog.Logger
	build   BuildInfo
	authz   Authorizer
	authn   *auth.Authenticator
	limiter ratelimit.Limiter
	tiers   ratelimit.TierTable
	checks  []Check
	// keysJWKS, when set, provides the JWKS served at GET /v1/keys/public. nil means
	// signing keys are not configured and the endpoint reports 503.
	keysJWKS func() any

	// Audit wiring (Task 1.6). When auditWriter is set the authorize handler enqueues
	// each decision for async persistence; when auditStore is set the decisions read
	// endpoints resolve records and compute signature_verified via verifyDecision.
	// retentionFor resolves a caller tier to its retention window (A#10); nil => none.
	auditWriter    *audit.Writer
	auditStore     audit.Store
	verifyDecision func(contractsv1.Decision) error
	retentionFor   func(tier string) time.Duration

	// idem, when set, caches a decision by (org, idempotency_key) so a repeated
	// request returns the same decision (Task 1.7). Best-effort: a cache miss or
	// error never blocks a decision.
	idem IdempotencyStore

	// Control plane (Task 2.2). When policySvc is set the /v1/policies endpoints are
	// mounted; bundleInvalidator (optional) forces the decision plane's cached bundle
	// to converge immediately after a same-process publish/rollback.
	policySvc         *policyctl.Service
	bundleInvalidator policyBundleInvalidator
	simulator         policySimulator

	// budget, when set, backs the two-phase budget lifecycle (Task 3.1/3.2): the engine
	// reserves during authorize, and capture/void settle the reservation here.
	budget budgetLifecycle
}

// IdempotencyStore caches a decision by (org, idempotency_key). Implementations:
// idempotency.Redis (shared, cross-instance) and idempotency.Mem (tests).
type IdempotencyStore interface {
	Lookup(ctx context.Context, orgID, idemKey string) (contractsv1.Decision, bool, error)
	Save(ctx context.Context, orgID, idemKey string, dec contractsv1.Decision) error
}

// WithKeys wires the public-key set served at GET /v1/keys/public (Task 1.5). fn
// returns a JSON-serializable JWKS document (e.g. signing.Keyring.JWKS()).
func (s *Server) WithKeys(fn func() any) *Server {
	s.keysJWKS = fn
	return s
}

// WithAudit wires the append-only decision log (Task 1.6): a writer for async
// persistence after the authorize response, a store for the read endpoints, and a
// verifier that recomputes a decision's Ed25519 signature at read time.
// retentionFor (optional) resolves a caller tier to its retention window (A#10).
func (s *Server) WithAudit(writer *audit.Writer, store audit.Store, verify func(contractsv1.Decision) error, retentionFor func(string) time.Duration) *Server {
	s.auditWriter = writer
	s.auditStore = store
	s.verifyDecision = verify
	s.retentionFor = retentionFor
	return s
}

// WithIdempotency wires the idempotency cache (Task 1.7). When set, a repeated
// authorize request carrying an already-seen idempotency_key returns the cached
// decision instead of evaluating again.
func (s *Server) WithIdempotency(store IdempotencyStore) *Server {
	s.idem = store
	return s
}

// New constructs a Server. Pass the Authorizer seam (decision engine), the
// Authenticator (request auth — TRD §11), the rate Limiter and its tier table
// (Task 1.3), and one Check per backing store.
func New(log *slog.Logger, build BuildInfo, authz Authorizer, authn *auth.Authenticator, limiter ratelimit.Limiter, tiers ratelimit.TierTable, checks ...Check) *Server {
	return &Server{log: log, build: build, authz: authz, authn: authn, limiter: limiter, tiers: tiers, checks: checks}
}

// Handler returns the fully wired HTTP handler, middleware and all.
//
// Middleware order (outermost first): requestID → recover → logRequests → routes.
// requestID runs first so both the panic handler and the access log see the id.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Register paths without a method so a method mismatch reaches our handler and
	// becomes a 7807 405 (Go's method-in-pattern would emit plain text instead).
	// /v1/authorize is protected: method guard (outermost, so a wrong method is a
	// 405 without needing credentials), then request authentication, then per-key
	// rate limiting (needs the authenticated tier), then the handler.
	authorize := s.authenticate(s.rateLimit(http.HandlerFunc(s.handleAuthorize)))
	mux.HandleFunc("/v1/authorize", s.method(http.MethodPost, authorize.ServeHTTP))
	// Two-phase budget (Task 3.1): commit or release a hold placed by a prior authorize.
	capture := s.authenticate(s.rateLimit(http.HandlerFunc(s.handleCapture)))
	mux.HandleFunc("/v1/authorize/{id}/capture", s.method(http.MethodPost, capture.ServeHTTP))
	voidH := s.authenticate(s.rateLimit(http.HandlerFunc(s.handleVoid)))
	mux.HandleFunc("/v1/authorize/{id}/void", s.method(http.MethodPost, voidH.ServeHTTP))
	// The decisions read endpoints are authenticated and org-scoped: a caller sees
	// only its own org's records (contract requires ApiKey/Signature/Nonce/Timestamp).
	getDecision := s.authenticate(s.rateLimit(http.HandlerFunc(s.handleGetDecision)))
	mux.HandleFunc("/v1/decisions/{id}", s.method(http.MethodGet, getDecision.ServeHTTP))
	listDecisions := s.authenticate(s.rateLimit(http.HandlerFunc(s.handleListDecisions)))
	mux.HandleFunc("/v1/decisions", s.method(http.MethodGet, listDecisions.ServeHTTP))
	// Control-plane policy endpoints (Task 2.2), mounted only when the control plane is
	// wired. Authenticated + rate-limited + org-scoped like the decisions read path.
	// The collection and item paths dispatch by method internally (thin 405s); the rest
	// are single-method. Go's mux prefers the literal /active over the {id} wildcard.
	if s.policySvc != nil {
		cp := func(h http.HandlerFunc) http.Handler { return s.authenticate(s.rateLimit(h)) }
		mux.Handle("/v1/policies", cp(s.handlePolicies))
		mux.Handle("/v1/policies/active", s.method(http.MethodGet, cp(s.handleActiveBundle).ServeHTTP))
		mux.Handle("/v1/policies/{id}", cp(s.handlePolicyItem))
		mux.Handle("/v1/policies/{id}/publish", s.method(http.MethodPost, cp(s.handlePublishPolicy).ServeHTTP))
		mux.Handle("/v1/policies/{id}/rollback", s.method(http.MethodPost, cp(s.handleRollbackPolicy).ServeHTTP))
		mux.Handle("/v1/policies/{id}/versions", s.method(http.MethodGet, cp(s.handleListVersions).ServeHTTP))
		mux.Handle("/v1/policies/{id}/simulate", s.method(http.MethodPost, cp(s.handleSimulate).ServeHTTP))
	}
	mux.HandleFunc("/v1/keys/public", s.method(http.MethodGet, s.handleKeysPublic))
	mux.HandleFunc("/v1/health", s.method(http.MethodGet, s.handleHealth))
	// Convenience alias for infra probes that hit the bare path.
	mux.HandleFunc("/health", s.method(http.MethodGet, s.handleHealth))
	// Catch-all: anything unrouted is a 7807 404 (not Go's plain-text default).
	mux.HandleFunc("/", s.handleNotFound)

	return s.requestID(s.recoverPanic(s.logRequests(mux)))
}

type healthResponse struct {
	Status string            `json:"status"`
	Build  BuildInfo         `json:"build"`
	Checks map[string]string `json:"checks"`
	Time   string            `json:"time"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	resp := healthResponse{
		Status: "ok",
		Build:  s.build,
		Checks: make(map[string]string, len(s.checks)),
		Time:   time.Now().UTC().Format(time.RFC3339),
	}
	code := http.StatusOK
	for _, c := range s.checks {
		if err := c.Ping(ctx); err != nil {
			resp.Checks[c.Name] = "error: " + err.Error()
			resp.Status = "degraded"
			code = http.StatusServiceUnavailable
			continue
		}
		resp.Checks[c.Name] = "ok"
	}

	writeJSON(w, code, resp)
}

// method guards a handler to a single HTTP method, emitting a 7807 405 (with an
// Allow header) for anything else. The catch-all "/" still 404s unknown paths.
func (s *Server) method(allowed string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != allowed {
			w.Header().Set("Allow", allowed)
			s.writeProblem(w, r, http.StatusMethodNotAllowed, codeMethodNotAllowed,
				"Method not allowed", "This endpoint does not support "+r.Method+".", nil)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

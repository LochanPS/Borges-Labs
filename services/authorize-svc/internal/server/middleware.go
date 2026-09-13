package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/trust-infra/authorize-svc/internal/auth"
	"github.com/trust-infra/authorize-svc/internal/ulid"
)

type ctxKey int

const (
	ctxKeyReqID ctxKey = iota
	ctxKeyLogger
	ctxKeyPrincipal
)

// requestHeaderName is the header the request id is echoed on, in and out. An
// inbound value is trusted for correlation; absent, one is minted.
const requestHeaderName = "X-Request-Id"

// requestID assigns a per-request id (inbound X-Request-Id if present, else a new
// ULID), stashes it plus a request-scoped logger in the context, and echoes it on
// the response so callers can correlate.
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestHeaderName)
		if id == "" {
			id = ulid.New()
		}
		w.Header().Set(requestHeaderName, id)

		l := s.log.With("request_id", id)
		ctx := context.WithValue(r.Context(), ctxKeyReqID, id)
		ctx = context.WithValue(ctx, ctxKeyLogger, l)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// secureHeaders sets defense-in-depth response headers on every response (TRD §20).
// This is a JSON API, not a browser app, but the headers are cheap and close off
// clickjacking / MIME-sniffing / referrer-leak vectors for any tooling that renders a
// response. A handler may still override a specific header afterwards (e.g. the public
// JWKS route sets its own Cache-Control).
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// Meaningful over TLS (production/ingress); harmless otherwise.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// API returns JSON only — lock the document down entirely.
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// reqID returns the request id stashed by the requestID middleware ("" if unset).
func reqID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyReqID).(string); ok {
		return v
	}
	return ""
}

// reqLogger returns the request-scoped logger, falling back to the default.
func reqLogger(r *http.Request) *slog.Logger {
	if v, ok := r.Context().Value(ctxKeyLogger).(*slog.Logger); ok {
		return v
	}
	return slog.Default()
}

// authMaxBodyBytes caps the body the auth middleware buffers to hash into the
// signature. It matches the authorize handler's own limit so a request that would be
// rejected as too large there is rejected here first, without reading more.
const authMaxBodyBytes = maxBodyBytes

// authenticate verifies the API key, HMAC signature, and nonce before the wrapped
// handler runs (TRD §11). It buffers the (length-limited) body so the signature can
// be checked over its exact bytes, then hands the same bytes to the handler. On any
// failure it writes an RFC 7807 body with the right status (401/403/replay) and does
// not call next. On success the authenticated principal is stashed in the context.
//
// It never logs the key, signature, or any secret — only the public key id and org.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limited := http.MaxBytesReader(w, r.Body, authMaxBodyBytes)
		body, err := io.ReadAll(limited)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				s.writeProblem(w, r, http.StatusRequestEntityTooLarge, codeValidationFailed,
					"Request too large", "The request body exceeds the maximum allowed size.", nil)
				return
			}
			s.writeProblem(w, r, http.StatusBadRequest, codeValidationFailed,
				"Malformed request", "The request body could not be read.", nil)
			return
		}
		// Restore the body for the downstream handler to decode.
		r.Body = io.NopCloser(bytes.NewReader(body))

		principal, aerr := s.authn.Authenticate(r.Context(), r.Method, r.URL.Path, r.Header, body)
		if aerr != nil {
			if aerr.Status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			reqLogger(r).Warn("auth rejected", "code", aerr.Code, "status", aerr.Status)
			s.writeProblem(w, r, aerr.Status, aerr.Code, aerr.Title, aerr.Detail, nil)
			return
		}

		reqLogger(r).Info("auth ok", "org_id", principal.OrgID, "key_id", principal.KeyID, "tier", principal.Tier)
		ctx := context.WithValue(r.Context(), ctxKeyPrincipal, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// principalOf returns the authenticated principal stashed by authenticate, and
// whether one was present.
func principalOf(r *http.Request) (auth.Principal, bool) {
	p, ok := r.Context().Value(ctxKeyPrincipal).(auth.Principal)
	return p, ok
}

// rateLimit enforces the per-key sliding-window and burst limits (TRD §11, Task
// 1.3). It runs AFTER authenticate, so the principal (and its tier) is known. On
// exceed it returns 429 with a Retry-After header. If the limiter's backing store
// errors it FAILS OPEN (allows the request) — a rate limit is a guardrail, and a
// Redis blip must not become a full outage; the event is logged.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalOf(r)
		if !ok {
			// authenticate always runs first; a missing principal is a wiring bug.
			s.writeProblem(w, r, http.StatusInternalServerError, codeInternal,
				"Internal server error", "Authentication context was not present.", nil)
			return
		}

		limits := s.tiers.Resolve(principal.Tier)
		d, err := s.limiter.Allow(r.Context(), principal.KeyID, limits)
		if err != nil {
			reqLogger(r).Warn("rate limit check failed; allowing", "err", err, "key_id", principal.KeyID)
			next.ServeHTTP(w, r)
			return
		}
		if !d.Allowed {
			secs := int(math.Ceil(d.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			reqLogger(r).Warn("rate limited", "key_id", principal.KeyID, "scope", d.Scope, "limit", d.Limit)
			s.writeProblem(w, r, http.StatusTooManyRequests, codeRateLimited,
				"Rate limit exceeded", "You have exceeded the "+d.Scope+" rate limit for your key.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// recoverPanic converts a panic in a downstream handler into a 7807 500 instead of
// dropping the connection. It logs the recovered value with the request id.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				reqLogger(r).Error("panic recovered", "panic", rec, "path", r.URL.Path)
				s.writeProblem(w, r, http.StatusInternalServerError, codeInternal,
					"Internal server error", "An unexpected error occurred.", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// logRequests emits one structured JSON line per request, carrying the request id.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		reqLogger(r).Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"latency_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

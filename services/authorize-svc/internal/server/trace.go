package server

import (
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/trust-infra/authorize-svc/internal/tracing"
)

// traceRequests starts a server span per request, propagating any inbound W3C
// tracecontext so a caller's SDK trace connects to ours (TRD §18). When tracing is
// disabled the global provider is a no-op, so this costs almost nothing. It runs after
// requestID so the request id is attached to the span for correlation.
func (s *Server) traceRequests(next http.Handler) http.Handler {
	tr := otel.Tracer(tracing.ServiceName)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := tr.Start(ctx, "HTTP "+r.Method, trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()

		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.path", r.URL.Path),
		)
		if id := reqID(r); id != "" {
			span.SetAttributes(attribute.String("request.id", id))
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))

		span.SetAttributes(attribute.Int("http.response.status_code", rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}
	})
}

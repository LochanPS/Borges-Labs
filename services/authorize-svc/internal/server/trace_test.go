package server

import (
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	noop "go.opentelemetry.io/otel/trace/noop"
)

// An authorize request emits an HTTP server span and a nested engine.authorize span
// carrying the verdict (TRD §18). Uses an in-memory exporter — no collector needed.
func TestTracing_SpansEmitted(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(noop.NewTracerProvider()) })

	h := newAuthHarness(t)
	resp, body := do(t, h.signedRequest(t, http.MethodPost, "/v1/authorize", validAuthorizeBody, h.active))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d; body: %s", resp.StatusCode, body)
	}

	spans := exp.GetSpans()
	byName := map[string]tracetest.SpanStub{}
	for _, s := range spans {
		byName[s.Name] = s
	}

	if _, ok := byName["HTTP POST"]; !ok {
		t.Errorf("missing HTTP server span; got %v", names(spans))
	}
	eng, ok := byName["engine.authorize"]
	if !ok {
		t.Fatalf("missing engine.authorize span; got %v", names(spans))
	}
	var sawVerdict bool
	for _, kv := range eng.Attributes {
		if string(kv.Key) == "verdict" && kv.Value.AsString() == "APPROVE" {
			sawVerdict = true
		}
	}
	if !sawVerdict {
		t.Errorf("engine.authorize span missing verdict=APPROVE attribute; attrs=%v", eng.Attributes)
	}
}

func names(spans tracetest.SpanStubs) []string {
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Name)
	}
	return out
}

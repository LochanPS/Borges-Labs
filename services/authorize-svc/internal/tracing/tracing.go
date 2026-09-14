// Package tracing wires OpenTelemetry tracing for the decision plane (TRD §18). It is
// off by default and adds effectively nothing to the hot path when disabled (the
// global no-op TracerProvider makes span starts cheap). Enable it by choosing an
// exporter via config: "stdout" (local debugging) or "otlp" (a collector).
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// ServiceName is the OTel resource service.name and the tracer name.
const ServiceName = "authorize-svc"

// Config selects the exporter. Exporter is "" / "none" (disabled), "stdout", or "otlp".
// For "otlp", Endpoint (e.g. https://collector:4318) is used when set; otherwise the
// standard OTEL_EXPORTER_OTLP_* environment is honored by the exporter.
type Config struct {
	Version  string
	Exporter string
	Endpoint string
}

// Init installs the global TracerProvider and W3C propagator. It always returns a
// non-nil shutdown func (a no-op when tracing is disabled), so callers can defer it
// unconditionally.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }

	var exp sdktrace.SpanExporter
	var err error
	switch cfg.Exporter {
	case "", "none", "off", "disabled":
		return noop, nil
	case "stdout":
		exp, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "otlp":
		opts := []otlptracehttp.Option{}
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpointURL(cfg.Endpoint))
		}
		exp, err = otlptracehttp.New(ctx, opts...)
	default:
		return noop, fmt.Errorf("tracing: unknown exporter %q (want stdout|otlp|none)", cfg.Exporter)
	}
	if err != nil {
		return noop, fmt.Errorf("tracing: build exporter: %w", err)
	}

	res, err := resource.New(ctx, resource.WithAttributes(
		attribute.String("service.name", ServiceName),
		attribute.String("service.version", cfg.Version),
	))
	if err != nil {
		return noop, fmt.Errorf("tracing: resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return tp.Shutdown, nil
}

// Tracer returns the service tracer from the global provider (a no-op tracer until
// Init installs a real provider).
func Tracer() trace.Tracer { return otel.Tracer(ServiceName) }

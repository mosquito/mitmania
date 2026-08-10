package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracesProvider bundles the SDK TracerProvider with the Tracer instances
// actually used to start spans.
type TracesProvider struct {
	Provider *sdktrace.TracerProvider
	Tracer   trace.Tracer
}

// setupTraces builds the traces sink named by rawURL — otlp+grpc://,
// otlp+http://, file:///path/, or stdout://. Empty rawURL
// disables traces entirely but still returns a fully usable
// TracerProvider (no exporter attached — every started span is simply
// discarded on End), the same "instrument creation always works, whether
// or not telemetry is enabled" posture as setupMetrics. sampleRatio
// governs a parent-based head sampler regardless of sink — an unsampled
// span is never even buffered for export.
func setupTraces(ctx context.Context, rawURL string, sampleRatio float64, res *sdkresource.Resource, spoolMaxSize int, spoolMaxAge time.Duration) (*TracesProvider, error) {
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRatio))

	if rawURL == "" {
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithSampler(sampler))
		return &TracesProvider{Provider: tp, Tracer: tp.Tracer("mitmania")}, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("telemetry: --otel-traces: invalid URL %q: %w", rawURL, err)
	}

	var exporter sdktrace.SpanExporter
	switch u.Scheme {
	case "otlp+grpc":
		opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(u.Host)}
		if insecureParam(u) {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		exporter, err = otlptracegrpc.New(ctx, opts...)
	case "otlp+http":
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host)}
		if insecureParam(u) {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	case "stdout":
		exporter, err = stdouttrace.New()
	case "file":
		if u.Path == "" {
			return nil, fmt.Errorf("telemetry: --otel-traces: file:// needs a path, got %q", rawURL)
		}
		exporter, err = newFileSpanExporter(u.Path, spoolMaxSize, spoolMaxAge)
	default:
		return nil, fmt.Errorf("telemetry: --otel-traces: unsupported scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("telemetry: traces exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res), sdktrace.WithSampler(sampler))
	return &TracesProvider{Provider: tp, Tracer: tp.Tracer("mitmania")}, nil
}

// insecureParam reads "?insecure=true" off an otlp+grpc/otlp+http sink
// URL — otherwise both default to TLS, matching every other network
// destination in this codebase (S3's own "?secure=false" opt-out is the
// closest precedent) and OTel's own OTEL_EXPORTER_OTLP_INSECURE naming.
func insecureParam(u *url.URL) bool {
	v, err := strconv.ParseBool(u.Query().Get("insecure"))
	return err == nil && v
}

// Shutdown flushes and closes the TracerProvider (and, transitively, its
// exporter).
func (p *TracesProvider) Shutdown(ctx context.Context) error {
	return p.Provider.Shutdown(ctx)
}

package storage

import (
	"context"
	"io"
	"log/slog"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"mitmania/internal/telemetry"
)

func discardLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func findStorageMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m, true
			}
		}
	}
	return metricdata.Metrics{}, false
}

func testPosixStorageT(t *testing.T) *PosixStorage {
	t.Helper()
	st, err := NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	return st
}

func TestWithTelemetry_RecordsOpDurationWithBackendLabel(t *testing.T) {
	st := testPosixStorageT(t)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	wrapped := WithTelemetry(st, metrics, nil)
	ctx := context.Background()
	if err := wrapped.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := wrapped.Get(ctx, "k"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dur, ok := findStorageMetric(t, &rm, "mitmania.storage.op.duration")
	if !ok {
		t.Fatalf("mitmania.storage.op.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 2 {
		t.Fatalf("storage.op.duration = %d data points, want 2 (put, get)", len(hist.DataPoints))
	}
	for _, dp := range hist.DataPoints {
		if v, ok := dp.Attributes.Value("backend"); !ok || v.AsString() != "posix" {
			t.Errorf("backend attribute = %v, ok=%v, want posix", v, ok)
		}
	}
}

func TestWithTelemetry_RecordsErrorResult(t *testing.T) {
	st := testPosixStorageT(t)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	wrapped := WithTelemetry(st, metrics, nil)
	ctx := context.Background()
	if _, err := wrapped.Stat(ctx, "does-not-exist"); err == nil {
		t.Fatalf("Stat: expected ErrNotExist")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dur, ok := findStorageMetric(t, &rm, "mitmania.storage.op.duration")
	if !ok {
		t.Fatalf("mitmania.storage.op.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 1 {
		t.Fatalf("storage.op.duration = %d data points, want 1", len(hist.DataPoints))
	}
	if v, ok := hist.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "error" {
		t.Errorf("result attribute = %v, ok=%v, want error", v, ok)
	}
}

func TestWithTelemetry_StartsSpanPerOp(t *testing.T) {
	st := testPosixStorageT(t)

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	wrapped := WithTelemetry(st, nil, tp.Tracer("test"))
	ctx := context.Background()
	if err := wrapped.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "storage" {
		t.Fatalf("spans = %v, want a single \"storage\" span", spans)
	}
}

func TestWithTelemetry_PreservesLinkerCapability(t *testing.T) {
	st := testPosixStorageT(t)
	wrapped := WithTelemetry(st, nil, nil)
	if _, ok := wrapped.(Linker); !ok {
		t.Fatalf("WithTelemetry did not preserve Linker capability for a backend that implements it")
	}
}

func TestWithTelemetry_NonLinkerBackendStaysNonLinker(t *testing.T) {
	wrapped := WithTelemetry(&nonLinkerStub{}, nil, nil)
	if _, ok := wrapped.(Linker); ok {
		t.Fatalf("WithTelemetry added Linker capability to a backend that doesn't implement it")
	}
}

func TestBackendName(t *testing.T) {
	if got := BackendName(testPosixStorageT(t)); got != "posix" {
		t.Errorf("BackendName(PosixStorage) = %q, want posix", got)
	}
	if got := BackendName(&nonLinkerStub{}); got != "unknown" {
		t.Errorf("BackendName(unknown) = %q, want unknown", got)
	}
}

// TestWithTelemetry_WrappingOrderDeterminesBackendLabel is a regression
// test for a real bug caught via a live scrape during manual testing:
// applying WithTelemetry AFTER WithLogging degrades the backend label to
// "unknown", since BackendName's type switch no longer sees through to
// *PosixStorage. WithTelemetry's own doc comment now says to wrap the raw
// store first — this test pins both the correct order (label = "posix")
// and documents what the wrong order actually produces (label =
// "unknown"), so a future refactor that silently reverses the order in
// cmd/mitmania is caught here, not by re-discovering the same bug live.
func TestWithTelemetry_WrappingOrderDeterminesBackendLabel(t *testing.T) {
	newMetrics := func(t *testing.T, reader *sdkmetric.ManualReader) *telemetry.Metrics {
		t.Helper()
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
		t.Cleanup(func() { mp.Shutdown(context.Background()) })
		m, err := telemetry.NewMetrics(mp.Meter("test"))
		if err != nil {
			t.Fatalf("NewMetrics: %v", err)
		}
		return m
	}
	backendLabelOf := func(t *testing.T, wrapped Storage, reader *sdkmetric.ManualReader) string {
		t.Helper()
		ctx := context.Background()
		if err := wrapped.Put(ctx, "k", []byte("v")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(ctx, &rm); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		dur, ok := findStorageMetric(t, &rm, "mitmania.storage.op.duration")
		if !ok {
			t.Fatalf("mitmania.storage.op.duration not recorded")
		}
		hist := dur.Data.(metricdata.Histogram[float64])
		v, ok := hist.DataPoints[0].Attributes.Value("backend")
		if !ok {
			t.Fatalf("backend attribute missing")
		}
		return v.AsString()
	}

	t.Run("correct order: WithTelemetry wraps the raw store", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		wrapped := WithLogging(WithTelemetry(testPosixStorageT(t), newMetrics(t, reader), nil), discardLogger(t))
		if got := backendLabelOf(t, wrapped, reader); got != "posix" {
			t.Errorf("backend = %q, want posix", got)
		}
	})

	t.Run("wrong order: WithTelemetry wraps an already-decorated store", func(t *testing.T) {
		reader := sdkmetric.NewManualReader()
		wrapped := WithTelemetry(WithLogging(testPosixStorageT(t), discardLogger(t)), newMetrics(t, reader), nil)
		if got := backendLabelOf(t, wrapped, reader); got != "unknown" {
			t.Errorf("backend = %q, want unknown (documenting the gotcha — see WithTelemetry's doc comment)", got)
		}
	})
}

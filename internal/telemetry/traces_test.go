package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestSetupTraces_EmptyURLDisabled(t *testing.T) {
	res, _ := buildResource("")
	tp, err := setupTraces(context.Background(), "", 0.1, res, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("setupTraces: %v", err)
	}
	defer tp.Shutdown(context.Background())

	if tp.Tracer == nil {
		t.Fatalf("Tracer is nil even when disabled")
	}
	// Must not panic even with no exporter attached.
	_, span := tp.Tracer.Start(context.Background(), "test")
	span.End()
}

func TestSetupTraces_RejectsUnsupportedScheme(t *testing.T) {
	res, _ := buildResource("")
	if _, err := setupTraces(context.Background(), "http://127.0.0.1:9090/metrics", 0.1, res, 128<<20, time.Hour); err == nil {
		t.Fatalf("expected an error for http:// (metrics-only, no traces equivalent)")
	}
}

func TestSetupTraces_StdoutSink(t *testing.T) {
	res, _ := buildResource("")
	tp, err := setupTraces(context.Background(), "stdout://", 1.0, res, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("setupTraces: %v", err)
	}
	defer tp.Shutdown(context.Background())

	_, span := tp.Tracer.Start(context.Background(), "test")
	span.End()
}

func TestSetupTraces_FileSink(t *testing.T) {
	dir := t.TempDir()
	res, _ := buildResource("")
	tp, err := setupTraces(context.Background(), "file://"+dir, 1.0, res, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("setupTraces: %v", err)
	}
	_, span := tp.Tracer.Start(context.Background(), "test")
	span.End()
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestSetupTraces_FileSinkRequiresPath(t *testing.T) {
	res, _ := buildResource("")
	if _, err := setupTraces(context.Background(), "file://", 1.0, res, 128<<20, time.Hour); err == nil {
		t.Fatalf("expected an error for file:// with no path")
	}
}

func TestSetupTraces_OTLPGRPCSink(t *testing.T) {
	res, _ := buildResource("")
	// No real collector listening — New() itself must still succeed
	// (otlptracegrpc connects lazily); only an actual export would fail,
	// and this test isn't exercising a real batch export.
	tp, err := setupTraces(context.Background(), "otlp+grpc://127.0.0.1:4317?insecure=true", 1.0, res, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("setupTraces: %v", err)
	}
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestSetupTraces_OTLPHTTPSink(t *testing.T) {
	res, _ := buildResource("")
	tp, err := setupTraces(context.Background(), "otlp+http://127.0.0.1:4318?insecure=true", 1.0, res, 128<<20, time.Hour)
	if err != nil {
		t.Fatalf("setupTraces: %v", err)
	}
	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

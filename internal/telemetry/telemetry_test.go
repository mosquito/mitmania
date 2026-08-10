package telemetry

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestSetup_FullyDisabledByDefault(t *testing.T) {
	p, err := Setup(context.Background(), Config{SpoolMaxSize: 128 << 20, SpoolMaxAge: time.Hour})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer p.Shutdown(context.Background())

	if p.MetricsAddr != "" {
		t.Errorf("MetricsAddr = %q, want empty — no scrape port opened when --otel-metrics is unset", p.MetricsAddr)
	}
	if p.M == nil {
		t.Fatalf("M (instruments) is nil even when disabled")
	}
	if p.Traces.Tracer == nil {
		t.Fatalf("Traces.Tracer is nil even when disabled")
	}

	// Every call site must still work: recording a metric and starting a
	// span must not panic even though nothing is exported anywhere.
	p.M.Request(context.Background(), "h1", "ok", "2xx", time.Millisecond)
	_, span := p.Traces.Tracer.Start(context.Background(), "test")
	span.End()
}

func TestSetup_MetricsEnabledOpensScrapePort(t *testing.T) {
	p, err := Setup(context.Background(), Config{
		MetricsURL:   "http://127.0.0.1:0/metrics",
		SpoolMaxSize: 128 << 20,
		SpoolMaxAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	defer p.Shutdown(context.Background())

	if p.MetricsAddr == "" {
		t.Fatalf("MetricsAddr empty despite --otel-metrics=http://...")
	}
	resp, err := http.Get("http://" + p.MetricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want 200", resp.StatusCode)
	}
}

func TestSetup_InvalidResourcePropagatesError(t *testing.T) {
	_, err := Setup(context.Background(), Config{Resource: "not-a-kv-pair", SpoolMaxSize: 128 << 20, SpoolMaxAge: time.Hour})
	if err == nil {
		t.Fatalf("expected an error for a malformed --otel-resource")
	}
}

func TestSetup_InvalidTracesSchemeCleansUpMetrics(t *testing.T) {
	// A failing traces sink must not leak the metrics provider/scrape
	// server it already started.
	_, err := Setup(context.Background(), Config{
		MetricsURL:   "http://127.0.0.1:0/metrics",
		TracesURL:    "not-a-valid://scheme",
		SpoolMaxSize: 128 << 20,
		SpoolMaxAge:  time.Hour,
	})
	if err == nil {
		t.Fatalf("expected an error for an unsupported --otel-traces scheme")
	}
}

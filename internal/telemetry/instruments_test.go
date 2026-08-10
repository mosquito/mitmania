package telemetry

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func findMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.Metrics {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	t.Fatalf("metric %q not found; have: %v", name, rm.ScopeMetrics)
	return metricdata.Metrics{}
}

func TestMetrics_NilReceiverIsNoOp(t *testing.T) {
	var m *Metrics
	ctx := context.Background()
	// None of these may panic on a nil *Metrics.
	m.ConnectionOpened(ctx, "http_proxy", "explicit")
	m.ConnectionClosed(ctx, "http_proxy", "explicit")
	m.Request(ctx, "h1", "ok", "2xx", time.Millisecond)
	m.BytesStreamed(ctx, "up", 1024)
	m.UpstreamDial(ctx, "h1", "ok", time.Millisecond)
	m.UpstreamTTFB(ctx, "h1", time.Millisecond)
	m.UpstreamReconnect(ctx, "goaway")
	m.TLSHandshake(ctx, "client", "ok", time.Millisecond)
	m.CertMint(ctx, "leaf")
	m.CertCache(ctx, "hotmap")
	m.CertDuration(ctx, "for", "miss", time.Millisecond)
	m.RuleCompile(ctx, "ok", time.Millisecond)
	m.RulesActiveClients(ctx, 1)
	m.OutcallResult(ctx, "webhook", "allow")
	m.OutcallInflight(ctx, 1)
	m.OutcallDuration(ctx, "webhook", "miss", time.Millisecond)
	m.OutcallCache(ctx, "hit")
	m.StorageOp(ctx, "get", "posix", "ok", time.Millisecond)
}

func TestMetrics_RequestRecordsCounterAndHistogram(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	m, err := NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	ctx := context.Background()
	m.Request(ctx, "h1", "ok", "2xx", 42*time.Millisecond)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	total := findMetric(t, &rm, "mitmania.requests.total")
	sum, ok := total.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("requests.total = %#v, want a single point with value 1", total.Data)
	}

	dur := findMetric(t, &rm, "mitmania.request.duration")
	hist, ok := dur.Data.(metricdata.Histogram[float64])
	if !ok || len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 {
		t.Fatalf("request.duration = %#v, want a single point with count 1", dur.Data)
	}
	if got := hist.DataPoints[0].Sum; got < 0.041 || got > 0.043 {
		t.Errorf("request.duration sum = %v, want ~0.042s", got)
	}
}

func TestMetrics_ConnectionOpenedAndClosedNetsToZero(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	m, err := NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	ctx := context.Background()
	m.ConnectionOpened(ctx, "https_proxy", "explicit")
	m.ConnectionOpened(ctx, "https_proxy", "explicit")
	m.ConnectionClosed(ctx, "https_proxy", "explicit")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	active := findMetric(t, &rm, "mitmania.connections.active")
	sum, ok := active.Data.(metricdata.Sum[int64])
	if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("connections.active = %#v, want a single point with value 1 (two opens, one close)", active.Data)
	}

	total := findMetric(t, &rm, "mitmania.connections.total")
	totalSum, ok := total.Data.(metricdata.Sum[int64])
	if !ok || len(totalSum.DataPoints) != 1 || totalSum.DataPoints[0].Value != 2 {
		t.Fatalf("connections.total = %#v, want a single point with value 2", total.Data)
	}
}

func TestMetrics_CertDurationCarriesCacheResultLabel(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	m, err := NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	ctx := context.Background()
	m.CertDuration(ctx, "for", "miss", 10*time.Millisecond)
	m.CertDuration(ctx, "for", "hotmap", time.Microsecond)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dur := findMetric(t, &rm, "mitmania.cert.duration")
	hist, ok := dur.Data.(metricdata.Histogram[float64])
	if !ok || len(hist.DataPoints) != 2 {
		t.Fatalf("cert.duration = %#v, want 2 distinct data points (one per cache_result)", dur.Data)
	}
}

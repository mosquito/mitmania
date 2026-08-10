package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"mitmania/internal/telemetry"
)

func findUpstreamMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
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

func TestNetDialer_DialTLS_RecordsDialAndHandshakeMetrics(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	dialer := NewUpstreamDialer(5*time.Second, 1, WithDialerMetrics(metrics), WithDialerTracer(tp.Tracer("test")))
	dst := ts.Listener.Addr().String()
	conn, err := dialer.DialTLS(context.Background(), "tcp", dst, "example.com")
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	dials, ok := findUpstreamMetric(t, &rm, "mitmania.upstream.dials.total")
	if !ok {
		t.Fatalf("mitmania.upstream.dials.total not recorded")
	}
	sum := dials.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("upstream.dials.total = %#v, want a single point with value 1", dials.Data)
	}
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "ok" {
		t.Errorf("result attribute = %v, ok=%v, want ok", v, ok)
	}

	dialDur, ok := findUpstreamMetric(t, &rm, "mitmania.upstream.dial.duration")
	if !ok {
		t.Fatalf("mitmania.upstream.dial.duration not recorded")
	}
	hist := dialDur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 1 {
		t.Fatalf("upstream.dial.duration = %d points, want 1", len(hist.DataPoints))
	}
	if v, ok := hist.DataPoints[0].Attributes.Value("proto"); !ok || v.AsString() != "h1" {
		t.Errorf("proto attribute = %v, ok=%v, want h1 (httptest.NewTLSServer doesn't negotiate h2)", v, ok)
	}

	hsDur, ok := findUpstreamMetric(t, &rm, "mitmania.tls.handshake.duration")
	if !ok {
		t.Fatalf("mitmania.tls.handshake.duration not recorded")
	}
	hsHist := hsDur.Data.(metricdata.Histogram[float64])
	if len(hsHist.DataPoints) != 1 {
		t.Fatalf("tls.handshake.duration = %d points, want 1", len(hsHist.DataPoints))
	}
	if v, ok := hsHist.DataPoints[0].Attributes.Value("leg"); !ok || v.AsString() != "upstream" {
		t.Errorf("leg attribute = %v, ok=%v, want upstream", v, ok)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "upstream.dial" {
		t.Fatalf("spans = %v, want a single \"upstream.dial\" span", spans)
	}
}

func TestNetDialer_DialTLS_RecordsFailureOnUnreachableHost(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	dialer := NewUpstreamDialer(300*time.Millisecond, 1, WithDialerMetrics(metrics))
	if _, err := dialer.DialTLS(context.Background(), "tcp", "127.0.0.1:1", "example.com"); err == nil {
		t.Fatalf("DialTLS: expected an error dialing a closed port")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dials, ok := findUpstreamMetric(t, &rm, "mitmania.upstream.dials.total")
	if !ok {
		t.Fatalf("mitmania.upstream.dials.total not recorded")
	}
	sum := dials.Data.(metricdata.Sum[int64])
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "refused" {
		t.Errorf("result attribute = %v, ok=%v, want refused", v, ok)
	}
}

func TestNetDialer_Dial_RecordsMetrics(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	dialer := NewUpstreamDialer(5*time.Second, 1, WithDialerMetrics(metrics))
	conn, err := dialer.Dial(context.Background(), "tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dials, ok := findUpstreamMetric(t, &rm, "mitmania.upstream.dials.total")
	if !ok {
		t.Fatalf("mitmania.upstream.dials.total not recorded")
	}
	sum := dials.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("upstream.dials.total = %#v, want a single point with value 1", dials.Data)
	}
}

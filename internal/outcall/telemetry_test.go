package outcall

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

func findOutcallMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
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

func TestService_RecordsAllowVerdictAndDuration(t *testing.T) {
	srv, _ := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusOK, Response{}, nil
	})

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	svc := NewService(2*time.Second, 2*time.Second, 8, WithMetrics(metrics))
	if _, err := svc.Do(context.Background(), "k1", Target{URL: srv.URL}, Request{Version: Version, Action: ActionWebhook}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findOutcallMetric(t, &rm, "mitmania.outcall.total")
	if !ok {
		t.Fatalf("mitmania.outcall.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("outcall.total = %#v, want a single point with value 1", total.Data)
	}
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "allow" {
		t.Errorf("result attribute = %v, ok=%v, want allow", v, ok)
	}

	dur, ok := findOutcallMetric(t, &rm, "mitmania.outcall.duration")
	if !ok {
		t.Fatalf("mitmania.outcall.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 {
		t.Fatalf("outcall.duration = %#v, want a single point with count 1", dur.Data)
	}
	if v, ok := hist.DataPoints[0].Attributes.Value("cache_result"); !ok || v.AsString() != "miss" {
		t.Errorf("cache_result attribute = %v, ok=%v, want miss (real network call)", v, ok)
	}
}

func TestService_RecordsDenyVerdict(t *testing.T) {
	srv, _ := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusForbidden, Response{Message: "no"}, nil
	})

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	svc := NewService(2*time.Second, 2*time.Second, 8, WithMetrics(metrics))
	if _, err := svc.Do(context.Background(), "k2", Target{URL: srv.URL}, Request{Version: Version, Action: ActionWebhook}); err == nil {
		t.Fatalf("Do: expected a DeniedError")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findOutcallMetric(t, &rm, "mitmania.outcall.total")
	if !ok {
		t.Fatalf("mitmania.outcall.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "deny" {
		t.Errorf("result attribute = %v, ok=%v, want deny", v, ok)
	}
}

func TestService_RecordsFailVerdictOnUnreachableBroker(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	svc := NewService(200*time.Millisecond, 200*time.Millisecond, 8, WithMetrics(metrics))
	if _, err := svc.Do(context.Background(), "k3", Target{URL: "https://127.0.0.1:1"}, Request{Version: Version, Action: ActionWebhook}); err == nil {
		t.Fatalf("Do: expected an error against an unreachable broker")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findOutcallMetric(t, &rm, "mitmania.outcall.total")
	if !ok {
		t.Fatalf("mitmania.outcall.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "fail" {
		t.Errorf("result attribute = %v, ok=%v, want fail", v, ok)
	}
}

func TestService_CacheHitRecordsHitCacheResult(t *testing.T) {
	srv, _ := jsonHandler(t, func(r *http.Request, n int32) (int, any, map[string]string) {
		return http.StatusOK, Response{}, map[string]string{"Cache-Control": "max-age=60"}
	})

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	svc := NewService(2*time.Second, 2*time.Second, 8, WithMetrics(metrics))

	ctx := context.Background()
	target := Target{URL: srv.URL}
	if _, err := svc.Do(ctx, "k4", target, Request{Version: Version, Action: ActionWebhook}); err != nil {
		t.Fatalf("Do (miss): %v", err)
	}
	if _, err := svc.Do(ctx, "k4", target, Request{Version: Version, Action: ActionWebhook}); err != nil {
		t.Fatalf("Do (hit): %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cacheTotal, ok := findOutcallMetric(t, &rm, "mitmania.outcall.cache.total")
	if !ok {
		t.Fatalf("mitmania.outcall.cache.total not recorded")
	}
	sum := cacheTotal.Data.(metricdata.Sum[int64])
	var sawHit, sawMiss bool
	for _, dp := range sum.DataPoints {
		if v, ok := dp.Attributes.Value("result"); ok {
			switch v.AsString() {
			case "hit":
				sawHit = true
			case "miss":
				sawMiss = true
			}
		}
	}
	if !sawHit || !sawMiss {
		t.Errorf("outcall.cache.total data points = %#v, want both hit and miss results", sum.DataPoints)
	}
}

func TestService_InjectsTraceparentIntoBrokerRequest(t *testing.T) {
	var gotTraceparent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	// A real, sampled span in ctx is what InjectAlways propagates —
	// without one there's nothing to inject.
	ctx, span := tp.Tracer("test").Start(context.Background(), "caller")
	defer span.End()

	svc := NewService(2*time.Second, 2*time.Second, 8)
	if _, err := svc.Do(ctx, "k5", Target{URL: srv.URL}, Request{Version: Version, Action: ActionWebhook}); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if gotTraceparent == "" {
		t.Fatalf("broker request carried no traceparent header — outcalls are mitmania's own dependency and must always propagate traceparent, regardless of --otel-propagate-upstream")
	}
}

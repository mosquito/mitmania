package rules

import (
	"context"
	"net/netip"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"mitmania/internal/telemetry"
)

func findRuleMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
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

func TestRuleEngine_RecordsCompileMetricsAndSpanOnFirstLoad(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.1")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(ctx)

	engine := NewRuleEngine(store, WithMetrics(metrics), WithTracer(tp.Tracer("test")))
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findRuleMetric(t, &rm, "mitmania.rules.compiles.total")
	if !ok {
		t.Fatalf("mitmania.rules.compiles.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("rules.compiles.total = %#v, want a single point with value 1", total.Data)
	}
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "ok" {
		t.Errorf("result attribute = %v, ok=%v, want ok", v, ok)
	}

	active, ok := findRuleMetric(t, &rm, "mitmania.rules.active_clients")
	if !ok {
		t.Fatalf("mitmania.rules.active_clients not recorded")
	}
	activeSum := active.Data.(metricdata.Sum[int64])
	if len(activeSum.DataPoints) != 1 || activeSum.DataPoints[0].Value != 1 {
		t.Fatalf("rules.active_clients = %#v, want a single point with value 1", active.Data)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "rules.compile" {
		t.Fatalf("spans = %v, want a single \"rules.compile\" span", spans)
	}
}

func TestRuleEngine_CachedLookupDoesNotRecompile(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.2")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	engine := NewRuleEngine(store, WithMetrics(metrics))

	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (first): %v", err)
	}
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (cached): %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findRuleMetric(t, &rm, "mitmania.rules.compiles.total")
	if !ok {
		t.Fatalf("mitmania.rules.compiles.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("rules.compiles.total = %#v, want value 1 (cached Lookup must not recompile)", total.Data)
	}
}

func TestRuleEngine_RecordsCompileFailure(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.3")
	if err := store.Save(ctx, client, []byte(`not valid json`)); err != nil {
		t.Fatal(err)
	}

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	engine := NewRuleEngine(store, WithMetrics(metrics))

	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("Lookup: expected a compile error for invalid JSON")
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	total, ok := findRuleMetric(t, &rm, "mitmania.rules.compiles.total")
	if !ok {
		t.Fatalf("mitmania.rules.compiles.total not recorded")
	}
	sum := total.Data.(metricdata.Sum[int64])
	if v, ok := sum.DataPoints[0].Attributes.Value("result"); !ok || v.AsString() != "error" {
		t.Errorf("result attribute = %v, ok=%v, want error", v, ok)
	}
}

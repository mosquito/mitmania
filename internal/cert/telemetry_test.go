package cert

import (
	"context"
	"crypto/x509"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"mitmania/internal/telemetry"
)

func findCertMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
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

func TestCertFactory_For_RecordsMintOnCacheMiss(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

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

	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck},
		WithFactoryMetrics(metrics), WithFactoryTracer(tp.Tracer("test")))

	fx := buildRealFixture(t, nil)
	if _, err := factory.For(ctx, "example.com", []*x509.Certificate{fx.leaf, fx.int}); err != nil {
		t.Fatalf("For: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	mints, ok := findCertMetric(t, &rm, "mitmania.cert.mints.total")
	if !ok {
		t.Fatalf("mitmania.cert.mints.total not recorded")
	}
	sum := mints.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Errorf("cert.mints.total = %#v, want a single point with value 1", mints.Data)
	}

	dur, ok := findCertMetric(t, &rm, "mitmania.cert.duration")
	if !ok {
		t.Fatalf("mitmania.cert.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 1 {
		t.Fatalf("cert.duration = %#v, want a single point with count 1", dur.Data)
	}

	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Name != "cert" {
		t.Fatalf("spans = %v, want a single \"cert\" span", spans)
	}
}

func TestCertFactory_For_CacheHitRecordsHotmap(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck}, WithFactoryMetrics(metrics))

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	if _, err := factory.For(ctx, "example.com", realChain); err != nil {
		t.Fatalf("For (mint): %v", err)
	}
	if _, err := factory.For(ctx, "example.com", realChain); err != nil {
		t.Fatalf("For (cache hit): %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	cacheTotal, ok := findCertMetric(t, &rm, "mitmania.cert.cache.total")
	if !ok {
		t.Fatalf("mitmania.cert.cache.total not recorded")
	}
	sum := cacheTotal.Data.(metricdata.Sum[int64])
	var sawMiss, sawHotmap bool
	for _, dp := range sum.DataPoints {
		if v, ok := dp.Attributes.Value("result"); ok {
			switch v.AsString() {
			case "miss":
				sawMiss = true
			case "hotmap":
				sawHotmap = true
			}
		}
	}
	if !sawMiss || !sawHotmap {
		t.Errorf("cert.cache.total data points = %#v, want both miss and hotmap results", sum.DataPoints)
	}
}

func TestCertFactory_Fallback_RecordsMint(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck}, WithFactoryMetrics(metrics))

	if _, err := factory.Fallback(ctx, "unreachable.example.com"); err != nil {
		t.Fatalf("Fallback: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	mints, ok := findCertMetric(t, &rm, "mitmania.cert.mints.total")
	if !ok {
		t.Fatalf("mitmania.cert.mints.total not recorded")
	}
	sum := mints.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("cert.mints.total = %#v, want a single point with value 1", mints.Data)
	}
	if v, ok := sum.DataPoints[0].Attributes.Value("kind"); !ok || v.AsString() != "fallback" {
		t.Errorf("kind attribute = %v, ok=%v, want fallback", v, ok)
	}
}

func TestCertFactory_SelfCert_RecordsMintAndCacheHit(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(ctx)
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck}, WithFactoryMetrics(metrics))

	names := []string{"Internal Proxy"}
	if _, err := factory.SelfCert(ctx, names); err != nil {
		t.Fatalf("SelfCert (mint): %v", err)
	}
	if _, err := factory.SelfCert(ctx, names); err != nil {
		t.Fatalf("SelfCert (cache hit): %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dur, ok := findCertMetric(t, &rm, "mitmania.cert.duration")
	if !ok {
		t.Fatalf("mitmania.cert.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 2 {
		t.Fatalf("cert.duration = %d data points, want 2 (op=selfcert x {miss,hotmap})", len(hist.DataPoints))
	}
}

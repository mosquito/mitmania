package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds every OpenTelemetry instrument this codebase emits. Every method is
// safe to call with a nil *Metrics (a no-op) — mirroring the nil-Logger/
// nil-Flow convention used throughout this codebase — so call sites never
// need a "is telemetry enabled" branch of their own; Setup already
// guarantees a non-nil *Metrics backed by a real (possibly no-export)
// MeterProvider whenever telemetry is wired in at all, but tests and
// standalone package use can pass nil freely.
type Metrics struct {
	connectionsActive metric.Int64UpDownCounter
	connectionsTotal  metric.Int64Counter
	requestsTotal     metric.Int64Counter
	requestDuration   metric.Float64Histogram
	bytesStreamed     metric.Int64Counter

	upstreamDialsTotal   metric.Int64Counter
	upstreamDialDuration metric.Float64Histogram
	upstreamTTFB         metric.Float64Histogram
	upstreamReconnects   metric.Int64Counter

	tlsHandshakeDuration metric.Float64Histogram

	certMintsTotal metric.Int64Counter
	certCacheTotal metric.Int64Counter
	certDuration   metric.Float64Histogram

	rulesCompilesTotal   metric.Int64Counter
	rulesActiveClients   metric.Int64UpDownCounter
	rulesCompileDuration metric.Float64Histogram

	outcallTotal      metric.Int64Counter
	outcallInflight   metric.Int64UpDownCounter
	outcallDuration   metric.Float64Histogram
	outcallCacheTotal metric.Int64Counter

	storageOpDuration metric.Float64Histogram
}

// NewMetrics builds every instrument declared on Metrics from meter. Called
// once at startup with the MeterProvider's meter (real or no-export, see
// setupMetrics) — never per-connection/per-request, since the SDK already
// deduplicates instrument creation by name but there's no reason to pay
// even that lookup cost repeatedly.
// secondsBuckets are the explicit bucket boundaries every duration
// histogram here uses, in seconds — the SDK's own DEFAULT boundaries
// (0,5,10,25,50,75,100,250,500,750,1000,...) are shaped for
// MILLISECOND-magnitude data by long-standing OTel convention; every
// value recorded here is float SECONDS (time.Duration.Seconds()), so
// using the defaults collapses every real measurement (sub-second, often
// sub-10ms) into the single [0,5] bucket — confirmed via a live scrape
// during manual testing, where a genuine ~3ms cert-mint call showed up
// with zero quantile resolution. Covers 100µs (cache-hit-fast-path) to
// 60s (this codebase's own longest default timeout, --http-timeout-read).
var secondsBuckets = []float64{0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

func NewMetrics(meter metric.Meter) (*Metrics, error) {
	m := &Metrics{}
	var err error
	reg := func(e error) {
		if e != nil && err == nil {
			err = e
		}
	}

	m.connectionsActive, err = meter.Int64UpDownCounter("mitmania.connections.active", metric.WithDescription("client connections currently open"))
	reg(err)
	m.connectionsTotal, err = meter.Int64Counter("mitmania.connections.total", metric.WithDescription("client connections accepted"))
	reg(err)
	m.requestsTotal, err = meter.Int64Counter("mitmania.requests.total", metric.WithDescription("requests handled"))
	reg(err)
	m.requestDuration, err = meter.Float64Histogram("mitmania.request.duration", metric.WithDescription("request handling latency"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)
	m.bytesStreamed, err = meter.Int64Counter("mitmania.bytes.streamed", metric.WithDescription("bytes relayed between client and upstream"), metric.WithUnit("By"))
	reg(err)

	m.upstreamDialsTotal, err = meter.Int64Counter("mitmania.upstream.dials.total", metric.WithDescription("upstream connection attempts"))
	reg(err)
	m.upstreamDialDuration, err = meter.Float64Histogram("mitmania.upstream.dial.duration", metric.WithDescription("upstream TCP+TLS dial latency"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)
	m.upstreamTTFB, err = meter.Float64Histogram("mitmania.upstream.ttfb", metric.WithDescription("time from request fully sent to the upstream response's first byte"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)
	m.upstreamReconnects, err = meter.Int64Counter("mitmania.upstream.reconnects.total", metric.WithDescription("upstream connections replaced mid-session"))
	reg(err)

	m.tlsHandshakeDuration, err = meter.Float64Histogram("mitmania.tls.handshake.duration", metric.WithDescription("TLS handshake latency, either leg"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)

	m.certMintsTotal, err = meter.Int64Counter("mitmania.cert.mints.total", metric.WithDescription("synthetic certificates freshly minted"))
	reg(err)
	m.certCacheTotal, err = meter.Int64Counter("mitmania.cert.cache.total", metric.WithDescription("certificate cache lookups"))
	reg(err)
	m.certDuration, err = meter.Float64Histogram("mitmania.cert.duration", metric.WithDescription("cert clone/fallback/self-cert call latency"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)

	m.rulesCompilesTotal, err = meter.Int64Counter("mitmania.rules.compiles.total", metric.WithDescription("rule file (re)compiles"))
	reg(err)
	m.rulesActiveClients, err = meter.Int64UpDownCounter("mitmania.rules.active_clients", metric.WithDescription("clients with a compiled rule set in memory"))
	reg(err)
	m.rulesCompileDuration, err = meter.Float64Histogram("mitmania.rules.compile.duration", metric.WithDescription("rule file parse+compile latency"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)

	m.outcallTotal, err = meter.Int64Counter("mitmania.outcall.total", metric.WithDescription("outcall (broker) calls"))
	reg(err)
	m.outcallInflight, err = meter.Int64UpDownCounter("mitmania.outcall.inflight", metric.WithDescription("outcalls currently in flight"))
	reg(err)
	m.outcallDuration, err = meter.Float64Histogram("mitmania.outcall.duration", metric.WithDescription("outcall latency, cache hits and real broker round trips both included (see cache_result)"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)
	m.outcallCacheTotal, err = meter.Int64Counter("mitmania.outcall.cache.total", metric.WithDescription("outcall response cache lookups"))
	reg(err)

	m.storageOpDuration, err = meter.Float64Histogram("mitmania.storage.op.duration", metric.WithDescription("Storage backend call latency"), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(secondsBuckets...))
	reg(err)

	if err != nil {
		return nil, fmt.Errorf("telemetry: instrument creation: %w", err)
	}
	return m, nil
}

func (m *Metrics) ConnectionOpened(ctx context.Context, listener, transport string) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(attribute.String("listener", listener), attribute.String("transport", transport))
	m.connectionsActive.Add(ctx, 1, attrs)
	m.connectionsTotal.Add(ctx, 1, attrs)
}

func (m *Metrics) ConnectionClosed(ctx context.Context, listener, transport string) {
	if m == nil {
		return
	}
	m.connectionsActive.Add(ctx, -1, metric.WithAttributes(attribute.String("listener", listener), attribute.String("transport", transport)))
}

func (m *Metrics) Request(ctx context.Context, proto, outcome, statusClass string, d time.Duration) {
	if m == nil {
		return
	}
	m.requestsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("proto", proto), attribute.String("outcome", outcome), attribute.String("status_class", statusClass)))
	m.requestDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("proto", proto)))
}

func (m *Metrics) BytesStreamed(ctx context.Context, direction string, n int64) {
	if m == nil || n == 0 {
		return
	}
	m.bytesStreamed.Add(ctx, n, metric.WithAttributes(attribute.String("direction", direction)))
}

func (m *Metrics) UpstreamDial(ctx context.Context, proto, result string, d time.Duration) {
	if m == nil {
		return
	}
	attrs := metric.WithAttributes(attribute.String("proto", proto), attribute.String("result", result))
	m.upstreamDialsTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	m.upstreamDialDuration.Record(ctx, d.Seconds(), attrs)
}

func (m *Metrics) UpstreamTTFB(ctx context.Context, proto string, d time.Duration) {
	if m == nil {
		return
	}
	m.upstreamTTFB.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("proto", proto)))
}

func (m *Metrics) UpstreamReconnect(ctx context.Context, reason string) {
	if m == nil {
		return
	}
	m.upstreamReconnects.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
}

func (m *Metrics) TLSHandshake(ctx context.Context, leg, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.tlsHandshakeDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("leg", leg), attribute.String("result", result)))
}

func (m *Metrics) CertMint(ctx context.Context, kind string) {
	if m == nil {
		return
	}
	m.certMintsTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("kind", kind)))
}

func (m *Metrics) CertCache(ctx context.Context, result string) {
	if m == nil {
		return
	}
	m.certCacheTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

func (m *Metrics) CertDuration(ctx context.Context, op, cacheResult string, d time.Duration) {
	if m == nil {
		return
	}
	m.certDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("op", op), attribute.String("cache_result", cacheResult)))
}

func (m *Metrics) RuleCompile(ctx context.Context, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.rulesCompilesTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
	m.rulesCompileDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("result", result)))
}

func (m *Metrics) RulesActiveClients(ctx context.Context, delta int64) {
	if m == nil {
		return
	}
	m.rulesActiveClients.Add(ctx, delta)
}

func (m *Metrics) OutcallResult(ctx context.Context, action, result string) {
	if m == nil {
		return
	}
	m.outcallTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("action", action), attribute.String("result", result)))
}

func (m *Metrics) OutcallInflight(ctx context.Context, delta int64) {
	if m == nil {
		return
	}
	m.outcallInflight.Add(ctx, delta)
}

func (m *Metrics) OutcallDuration(ctx context.Context, action, cacheResult string, d time.Duration) {
	if m == nil {
		return
	}
	m.outcallDuration.Record(ctx, d.Seconds(), metric.WithAttributes(attribute.String("action", action), attribute.String("cache_result", cacheResult)))
}

func (m *Metrics) OutcallCache(ctx context.Context, result string) {
	if m == nil {
		return
	}
	m.outcallCacheTotal.Add(ctx, 1, metric.WithAttributes(attribute.String("result", result)))
}

func (m *Metrics) StorageOp(ctx context.Context, op, backend, result string, d time.Duration) {
	if m == nil {
		return
	}
	m.storageOpDuration.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("op", op), attribute.String("backend", backend), attribute.String("result", result)))
}

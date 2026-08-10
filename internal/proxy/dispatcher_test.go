package proxy

import (
	"context"
	"net"
	"net/netip"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/session"
	"mitmania/internal/telemetry"
)

type stubHandler struct {
	served bool
	gotCtx context.Context
}

func (h *stubHandler) Serve(ctx context.Context, sess session.Session, dialer UpstreamDialer) {
	h.served = true
	h.gotCtx = ctx
}

func testSession() session.Session {
	c1, c2 := net.Pipe()
	c2.Close()
	return session.Session{
		Client:    netip.MustParseAddrPort("127.0.0.1:12345"),
		Transport: session.TransportExplicit,
		Conn:      c1,
		Acceptor:  "http_proxy",
	}
}

func TestDispatcher_HandleWithoutTelemetryStillServes(t *testing.T) {
	h := &stubHandler{}
	d := &Dispatcher{Selector: &Selector{Default: h}}
	d.Handle(context.Background(), testSession())
	if !h.served {
		t.Fatalf("handler was not served")
	}
}

func TestDispatcher_RecordsConnectionMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	h := &stubHandler{}
	d := &Dispatcher{Selector: &Selector{Default: h}, Metrics: metrics}
	d.Handle(context.Background(), testSession())

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var total, active metricdata.Metrics
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "mitmania.connections.total":
				total = m
			case "mitmania.connections.active":
				active = m
			}
		}
	}
	if sum, ok := total.Data.(metricdata.Sum[int64]); !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("connections.total = %#v, want a single point with value 1", total.Data)
	}
	// Handle already returned (ConnectionClosed deferred and run), so
	// active should have netted back to 0.
	if sum, ok := active.Data.(metricdata.Sum[int64]); !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 0 {
		t.Fatalf("connections.active = %#v, want a single point with value 0 (opened then closed)", active.Data)
	}
}

func TestDispatcher_StartsRootSpanAndPassesItDown(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())

	h := &stubHandler{}
	d := &Dispatcher{Selector: &Selector{Default: h}, Tracer: tp.Tracer("test")}
	d.Handle(context.Background(), testSession())

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Name != "connection" {
		t.Errorf("span name = %q, want connection", spans[0].Name)
	}

	if h.gotCtx == nil {
		t.Fatalf("handler did not receive a context")
	}
	if sc := trace.SpanContextFromContext(h.gotCtx); !sc.IsValid() {
		t.Fatalf("ctx passed to the handler carries no span — child spans wouldn't nest under the root")
	}
}

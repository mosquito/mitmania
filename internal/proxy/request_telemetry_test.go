package proxy

import (
	"context"
	"fmt"
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

func findRequestMetric(t *testing.T, rm *metricdata.ResourceMetrics, name string) (metricdata.Metrics, bool) {
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

// waitForRequestMetric polls reader for name, giving the server goroutine
// time to finish its post-response bookkeeping (logAccess's metric record)
// relative to the client having already read the response — the client
// seeing response bytes on the wire says nothing about whether the
// server-side handler has reached its own logAccess call yet.
func waitForRequestMetric(t *testing.T, reader *sdkmetric.ManualReader, name string) metricdata.Metrics {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var rm metricdata.ResourceMetrics
	for time.Now().Before(deadline) {
		if err := reader.Collect(context.Background(), &rm); err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if m, ok := findRequestMetric(t, &rm, name); ok {
			return m
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for metric %q to be recorded", name)
	return metricdata.Metrics{}
}

func TestHTTP1Handler_ConnectRoundTrip_RecordsRequestSpanAndMetric(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, path=%s", r.URL.Path)
	}))
	defer origin.Close()
	defer origin.CloseClientConnections()

	handler, caPEM := newHappyPathHandler(t)

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

	handler.Metrics = metrics
	handler.Tracer = tp.Tracer("test")

	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	total := waitForRequestMetric(t, reader, "mitmania.requests.total")
	sum := total.Data.(metricdata.Sum[int64])
	if len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
		t.Fatalf("requests.total = %#v, want a single point with value 1", total.Data)
	}
	attrs := sum.DataPoints[0].Attributes
	if v, ok := attrs.Value("proto"); !ok || v.AsString() != "h1" {
		t.Errorf("proto attribute = %v, ok=%v, want h1", v, ok)
	}
	if v, ok := attrs.Value("outcome"); !ok || v.AsString() != "ok" {
		t.Errorf("outcome attribute = %v, ok=%v, want ok", v, ok)
	}
	if v, ok := attrs.Value("status_class"); !ok || v.AsString() != "2xx" {
		t.Errorf("status_class attribute = %v, ok=%v, want 2xx", v, ok)
	}

	var reqSpan *tracetest.SpanStub
	for i, s := range exporter.GetSpans() {
		if s.Name == "request" {
			reqSpan = &exporter.GetSpans()[i]
		}
	}
	if reqSpan == nil {
		t.Fatalf("no \"request\" span recorded; spans: %v", exporter.GetSpans())
	}
	var gotDst string
	for _, a := range reqSpan.Attributes {
		if string(a.Key) == "dst" {
			gotDst = a.Value.AsString()
		}
	}
	wantDst := origin.Listener.Addr().String() // origin.URL's host:port is already a resolved 127.0.0.1:PORT literal
	if gotDst != wantDst {
		t.Errorf("request span dst = %q, want %q (the resolved upstream address, not just the domain in url)", gotDst, wantDst)
	}
}

// findSpan returns the first exported span with the given name, optionally
// filtered by a predicate over its attributes (needed here since "request"
// names both the CONNECT-phase span and the actual per-request span within
// the tunnel — same Name, different attributes).
func findSpan(spans tracetest.SpanStubs, name string, match func(tracetest.SpanStub) bool) *tracetest.SpanStub {
	for i, s := range spans {
		if s.Name == name && (match == nil || match(s)) {
			return &spans[i]
		}
	}
	return nil
}

func spanAttr(s tracetest.SpanStub, key string) (string, bool) {
	for _, a := range s.Attributes {
		if string(a.Key) == key {
			return a.Value.AsString(), true
		}
	}
	return "", false
}

func spanBoolAttr(s tracetest.SpanStub, key string) (bool, bool) {
	for _, a := range s.Attributes {
		if string(a.Key) == key {
			return a.Value.AsBool(), true
		}
	}
	return false, false
}

func spanIntAttr(s tracetest.SpanStub, key string) (int64, bool) {
	for _, a := range s.Attributes {
		if string(a.Key) == key {
			return a.Value.AsInt64(), true
		}
	}
	return 0, false
}

func hasMethodGET(s tracetest.SpanStub) bool {
	v, ok := spanAttr(s, "method")
	return ok && v == "GET"
}

// TestHTTP1Handler_UpstreamSpanTree_H1 verifies the per-request upstream
// telemetry waterfall for the h1 upstream leg: "request" -> "upstream" ->
// "upstream.connect"/"upstream.request"/"upstream.response", each a real
// child span (not just a flat list sharing a trace id), with
// "upstream.connect" reporting reused=true — this GET reuses the same
// upstream TLS connection TLSService.Terminate already dialed to fetch the
// real cert to clone, no fresh dial for this specific request.
func TestHTTP1Handler_UpstreamSpanTree_H1(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, path=%s", r.URL.Path)
	}))
	defer origin.Close()
	defer origin.CloseClientConnections()

	handler, caPEM := newHappyPathHandler(t)
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer tp.Shutdown(context.Background())
	handler.Tracer = tp.Tracer("test")

	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	spans := exporter.GetSpans()

	reqSpan := findSpan(spans, "request", hasMethodGET)
	if reqSpan == nil {
		t.Fatalf("no per-request \"request\" span (method=GET) found; spans: %v", spanNames(spans))
	}
	upstreamSpan := findSpan(spans, "upstream", nil)
	if upstreamSpan == nil {
		t.Fatalf("no \"upstream\" span found; spans: %v", spanNames(spans))
	}
	if upstreamSpan.Parent.SpanID() != reqSpan.SpanContext.SpanID() {
		t.Errorf("\"upstream\" span's parent = %s, want the request span %s", upstreamSpan.Parent.SpanID(), reqSpan.SpanContext.SpanID())
	}
	if got, ok := spanAttr(*upstreamSpan, "proto"); !ok || got != "h1" {
		t.Errorf("\"upstream\" span proto = %v, ok=%v, want h1", got, ok)
	}

	for _, name := range []string{"upstream.connect", "upstream.request", "upstream.response"} {
		child := findSpan(spans, name, func(s tracetest.SpanStub) bool {
			return s.Parent.SpanID() == upstreamSpan.SpanContext.SpanID()
		})
		if child == nil {
			t.Errorf("no %q span parented under \"upstream\"; spans: %v", name, spanNames(spans))
		}
	}

	connectSpan := findSpan(spans, "upstream.connect", func(s tracetest.SpanStub) bool {
		return s.Parent.SpanID() == upstreamSpan.SpanContext.SpanID()
	})
	if reused, ok := spanBoolAttr(*connectSpan, "reused"); !ok || !reused {
		t.Errorf("\"upstream.connect\" reused = %v, ok=%v, want true (this GET reuses TLSService.Terminate's dial)", reused, ok)
	}

	respSpan := findSpan(spans, "upstream.response", func(s tracetest.SpanStub) bool {
		return s.Parent.SpanID() == upstreamSpan.SpanContext.SpanID()
	})
	if status, ok := spanIntAttr(*respSpan, "status"); !ok || status != 200 {
		t.Errorf("\"upstream.response\" status = %v, ok=%v, want 200", status, ok)
	}
}

func spanNames(spans tracetest.SpanStubs) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name
	}
	return names
}

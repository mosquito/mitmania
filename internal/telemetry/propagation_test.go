package telemetry

import (
	"context"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func spanContext() trace.SpanContext {
	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("0102030405060708")
	return trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
}

func TestInjectAlways_WritesTraceparent(t *testing.T) {
	ctx := trace.ContextWithSpanContext(context.Background(), spanContext())
	h := http.Header{}
	InjectAlways(ctx, h)
	if h.Get("traceparent") == "" {
		t.Fatalf("traceparent header not written")
	}
}

func TestInjectUpstream_DisabledByDefault(t *testing.T) {
	ctx := trace.ContextWithSpanContext(context.Background(), spanContext())
	h := http.Header{}
	InjectUpstream(ctx, h, false)
	if h.Get("traceparent") != "" {
		t.Fatalf("traceparent header written despite enabled=false (stealth-by-default violated)")
	}
}

func TestInjectUpstream_EnabledOptIn(t *testing.T) {
	ctx := trace.ContextWithSpanContext(context.Background(), spanContext())
	h := http.Header{}
	InjectUpstream(ctx, h, true)
	if h.Get("traceparent") == "" {
		t.Fatalf("traceparent header not written despite enabled=true")
	}
}

func TestExtractClient_IgnoredByDefault(t *testing.T) {
	h := http.Header{}
	InjectAlways(trace.ContextWithSpanContext(context.Background(), spanContext()), h)

	got := ExtractClient(context.Background(), h, false)
	if sc := trace.SpanContextFromContext(got); sc.IsValid() {
		t.Fatalf("client-supplied traceparent was adopted despite enabled=false (client must not drive our trace ids by default)")
	}
}

func TestExtractClient_EnabledAdoptsParent(t *testing.T) {
	h := http.Header{}
	InjectAlways(trace.ContextWithSpanContext(context.Background(), spanContext()), h)

	got := ExtractClient(context.Background(), h, true)
	sc := trace.SpanContextFromContext(got)
	if !sc.IsValid() || sc.TraceID() != spanContext().TraceID() {
		t.Fatalf("client-supplied traceparent not adopted despite enabled=true: %+v", sc)
	}
}

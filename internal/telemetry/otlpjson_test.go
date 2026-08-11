package telemetry

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	oteltrace "go.opentelemetry.io/otel/trace"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// valueToOTLP is the widest untested surface in this file: every
// attribute.Type has its own oneof arm, and the file_exporter tests only
// ever exercise spans with no attributes at all.
func TestValueToOTLP_AllAttributeTypes(t *testing.T) {
	cases := []struct {
		name string
		val  attribute.Value
		want func(*testing.T, *commonpb.AnyValue)
	}{
		{
			name: "bool",
			val:  attribute.BoolValue(true),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				if got := v.GetBoolValue(); got != true {
					t.Errorf("BoolValue = %v, want true", got)
				}
			},
		},
		{
			name: "int64",
			val:  attribute.Int64Value(42),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				if got := v.GetIntValue(); got != 42 {
					t.Errorf("IntValue = %v, want 42", got)
				}
			},
		},
		{
			name: "float64",
			val:  attribute.Float64Value(3.5),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				if got := v.GetDoubleValue(); got != 3.5 {
					t.Errorf("DoubleValue = %v, want 3.5", got)
				}
			},
		},
		{
			name: "string",
			val:  attribute.StringValue("hi"),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				if got := v.GetStringValue(); got != "hi" {
					t.Errorf("StringValue = %q, want hi", got)
				}
			},
		},
		{
			name: "boolslice",
			val:  attribute.BoolSliceValue([]bool{true, false}),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				arr := v.GetArrayValue().GetValues()
				if len(arr) != 2 || arr[0].GetBoolValue() != true || arr[1].GetBoolValue() != false {
					t.Errorf("ArrayValue = %v, want [true false]", arr)
				}
			},
		},
		{
			name: "int64slice",
			val:  attribute.Int64SliceValue([]int64{1, 2, 3}),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				arr := v.GetArrayValue().GetValues()
				if len(arr) != 3 || arr[0].GetIntValue() != 1 || arr[2].GetIntValue() != 3 {
					t.Errorf("ArrayValue = %v, want [1 2 3]", arr)
				}
			},
		},
		{
			name: "float64slice",
			val:  attribute.Float64SliceValue([]float64{1.5, 2.5}),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				arr := v.GetArrayValue().GetValues()
				if len(arr) != 2 || arr[0].GetDoubleValue() != 1.5 || arr[1].GetDoubleValue() != 2.5 {
					t.Errorf("ArrayValue = %v, want [1.5 2.5]", arr)
				}
			},
		},
		{
			name: "stringslice",
			val:  attribute.StringSliceValue([]string{"a", "b"}),
			want: func(t *testing.T, v *commonpb.AnyValue) {
				arr := v.GetArrayValue().GetValues()
				if len(arr) != 2 || arr[0].GetStringValue() != "a" || arr[1].GetStringValue() != "b" {
					t.Errorf("ArrayValue = %v, want [a b]", arr)
				}
			},
		},
		{
			// The zero Value has Type() == attribute.INVALID, which is not
			// one of the explicit cases — this is the only way to reach the
			// default branch (fall back to v.String()).
			name: "invalid falls back to String()",
			val:  attribute.Value{},
			want: func(t *testing.T, v *commonpb.AnyValue) {
				want := attribute.Value{}.String()
				if got := v.GetStringValue(); got != want {
					t.Errorf("StringValue = %q, want %q (v.String() fallback)", got, want)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := valueToOTLP(tc.val)
			if got == nil {
				t.Fatal("valueToOTLP returned nil")
			}
			tc.want(t, got)
		})
	}
}

func TestAttrsToOTLP_EmptyReturnsNil(t *testing.T) {
	if got := attrsToOTLP(nil); got != nil {
		t.Errorf("attrsToOTLP(nil) = %v, want nil", got)
	}
	if got := attrsToOTLP([]attribute.KeyValue{}); got != nil {
		t.Errorf("attrsToOTLP(empty) = %v, want nil", got)
	}
}

func TestAttrsToOTLP_ConvertsKeyAndValue(t *testing.T) {
	attrs := []attribute.KeyValue{attribute.String("k", "v")}
	got := attrsToOTLP(attrs)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Key != "k" || got[0].Value.GetStringValue() != "v" {
		t.Errorf("got %+v, want key=k value=v", got[0])
	}
}

func TestStatusCodeToOTLP(t *testing.T) {
	cases := []struct {
		in   codes.Code
		want tracepb.Status_StatusCode
	}{
		{codes.Ok, tracepb.Status_STATUS_CODE_OK},
		{codes.Error, tracepb.Status_STATUS_CODE_ERROR},
		{codes.Unset, tracepb.Status_STATUS_CODE_UNSET},
	}
	for _, tc := range cases {
		if got := statusCodeToOTLP(tc.in); got != tc.want {
			t.Errorf("statusCodeToOTLP(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func mustSpanContext(t *testing.T, traceIDByte, spanIDByte byte) oteltrace.SpanContext {
	t.Helper()
	var traceID oteltrace.TraceID
	var spanID oteltrace.SpanID
	for i := range traceID {
		traceID[i] = traceIDByte
	}
	for i := range spanID {
		spanID[i] = spanIDByte
	}
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: oteltrace.FlagsSampled,
	})
}

// spanToOTLP's parent-span-ID assignment, and its Events/Links loops, are
// only reached when a span actually carries a parent, events, or links —
// the file_exporter tests only ever produce bare root spans.
func TestSpanToOTLP_ParentEventsAndLinks(t *testing.T) {
	childCtx := mustSpanContext(t, 0x01, 0x02)
	parentCtx := mustSpanContext(t, 0x01, 0x03)
	linkCtx := mustSpanContext(t, 0x04, 0x05)

	start := time.Unix(1000, 0)
	end := start.Add(time.Second)
	eventTime := start.Add(500 * time.Millisecond)

	stub := tracetest.SpanStub{
		Name:        "child-span",
		SpanContext: childCtx,
		Parent:      parentCtx,
		SpanKind:    oteltrace.SpanKindServer,
		StartTime:   start,
		EndTime:     end,
		Attributes:  []attribute.KeyValue{attribute.Int("n", 1)},
		Events: []sdktrace.Event{{
			Name:                  "ev",
			Time:                  eventTime,
			Attributes:            []attribute.KeyValue{attribute.String("k", "v")},
			DroppedAttributeCount: 2,
		}},
		Links: []sdktrace.Link{{
			SpanContext:           linkCtx,
			Attributes:            []attribute.KeyValue{attribute.Bool("linked", true)},
			DroppedAttributeCount: 3,
		}},
		Status: sdktrace.Status{Code: codes.Error, Description: "boom"},
	}

	got := spanToOTLP(stub.Snapshot())

	wantParentID := parentCtx.SpanID()
	if string(got.ParentSpanId) != string(wantParentID[:]) {
		t.Errorf("ParentSpanId = %x, want %x", got.ParentSpanId, wantParentID[:])
	}

	if len(got.Events) != 1 {
		t.Fatalf("Events = %d, want 1", len(got.Events))
	}
	ev := got.Events[0]
	if ev.Name != "ev" || ev.DroppedAttributesCount != 2 || len(ev.Attributes) != 1 {
		t.Errorf("event = %+v, want name=ev dropped=2 1 attr", ev)
	}
	if ev.TimeUnixNano != uint64(eventTime.UnixNano()) {
		t.Errorf("event time = %d, want %d", ev.TimeUnixNano, eventTime.UnixNano())
	}

	if len(got.Links) != 1 {
		t.Fatalf("Links = %d, want 1", len(got.Links))
	}
	link := got.Links[0]
	wantLinkSpanID := linkCtx.SpanID()
	if string(link.SpanId) != string(wantLinkSpanID[:]) {
		t.Errorf("link SpanId = %x, want %x", link.SpanId, wantLinkSpanID[:])
	}
	if link.DroppedAttributesCount != 3 || len(link.Attributes) != 1 {
		t.Errorf("link = %+v, want dropped=3 1 attr", link)
	}

	if got.Status.Code != tracepb.Status_STATUS_CODE_ERROR || got.Status.Message != "boom" {
		t.Errorf("Status = %+v, want ERROR/boom", got.Status)
	}
}

func TestSpanToOTLP_NoParentLeavesParentSpanIdEmpty(t *testing.T) {
	stub := tracetest.SpanStub{
		Name:        "root-span",
		SpanContext: mustSpanContext(t, 0x06, 0x07),
		StartTime:   time.Unix(2000, 0),
		EndTime:     time.Unix(2001, 0),
	}
	got := spanToOTLP(stub.Snapshot())
	if len(got.ParentSpanId) != 0 {
		t.Errorf("ParentSpanId = %x, want empty for a root span", got.ParentSpanId)
	}
}

// spansToOTLP groups spans by InstrumentationScope; with a single scope
// (the only shape file_exporter_test.go exercises) the grouping map and
// the multi-key append path never run more than once.
func TestSpansToOTLP_GroupsByInstrumentationScope(t *testing.T) {
	mk := func(name, scopeName string) sdktrace.ReadOnlySpan {
		return tracetest.SpanStub{
			Name:                 name,
			SpanContext:          mustSpanContext(t, 0x08, 0x09),
			StartTime:            time.Unix(3000, 0),
			EndTime:              time.Unix(3001, 0),
			InstrumentationScope: instrumentation.Scope{Name: scopeName, Version: "v1"},
		}.Snapshot()
	}

	spans := []sdktrace.ReadOnlySpan{
		mk("a1", "scope-a"),
		mk("b1", "scope-b"),
		mk("a2", "scope-a"),
	}

	req := spansToOTLP(spans)
	if len(req.ResourceSpans) != 1 {
		t.Fatalf("ResourceSpans = %d, want 1", len(req.ResourceSpans))
	}
	scopeSpans := req.ResourceSpans[0].ScopeSpans
	if len(scopeSpans) != 2 {
		t.Fatalf("ScopeSpans = %d, want 2 (scope-a, scope-b)", len(scopeSpans))
	}
	if scopeSpans[0].Scope.Name != "scope-a" || len(scopeSpans[0].Spans) != 2 {
		t.Errorf("scopeSpans[0] = %+v, want scope-a with 2 spans", scopeSpans[0])
	}
	if scopeSpans[1].Scope.Name != "scope-b" || len(scopeSpans[1].Spans) != 1 {
		t.Errorf("scopeSpans[1] = %+v, want scope-b with 1 span", scopeSpans[1])
	}
}

func TestSpansToOTLP_EmptyReturnsEmptyRequest(t *testing.T) {
	req := spansToOTLP(nil)
	if len(req.ResourceSpans) != 0 {
		t.Errorf("ResourceSpans = %d, want 0 for an empty batch", len(req.ResourceSpans))
	}
}

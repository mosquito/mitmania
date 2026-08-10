package telemetry

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// spansToOTLP converts a batch of SDK spans into a real
// ExportTraceServiceRequest — the same wire shape an OTLP/HTTP+JSON
// collector endpoint accepts, and what an otel-collector filelog
// receiver + OTLP-JSON parser is built to read. Spans are grouped
// by InstrumentationScope (name+version) into separate ScopeSpans, all
// under one ResourceSpans — every span in one process shares the same
// Resource (one per TracerProvider), so there's no need to also group by
// resource identity the way a multi-tenant collector would.
func spansToOTLP(spans []sdktrace.ReadOnlySpan) *collectortracepb.ExportTraceServiceRequest {
	if len(spans) == 0 {
		return &collectortracepb.ExportTraceServiceRequest{}
	}

	type scopeKey struct{ name, version string }
	order := make([]scopeKey, 0, 1)
	byScope := make(map[scopeKey][]*tracepb.Span)

	for _, s := range spans {
		key := scopeKey{name: s.InstrumentationScope().Name, version: s.InstrumentationScope().Version}
		if _, ok := byScope[key]; !ok {
			order = append(order, key)
		}
		byScope[key] = append(byScope[key], spanToOTLP(s))
	}

	scopeSpans := make([]*tracepb.ScopeSpans, 0, len(order))
	for _, key := range order {
		scopeSpans = append(scopeSpans, &tracepb.ScopeSpans{
			Scope: &commonpb.InstrumentationScope{Name: key.name, Version: key.version},
			Spans: byScope[key],
		})
	}

	return &collectortracepb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource:   resourceToOTLP(spans[0].Resource().Attributes()),
			ScopeSpans: scopeSpans,
		}},
	}
}

func resourceToOTLP(attrs []attribute.KeyValue) *resourcepb.Resource {
	return &resourcepb.Resource{Attributes: attrsToOTLP(attrs)}
}

func spanToOTLP(s sdktrace.ReadOnlySpan) *tracepb.Span {
	sc := s.SpanContext()
	traceID := sc.TraceID()
	spanID := sc.SpanID()

	span := &tracepb.Span{
		TraceId:                traceID[:],
		SpanId:                 spanID[:],
		TraceState:             sc.TraceState().String(),
		Name:                   s.Name(),
		Kind:                   spanKindToOTLP(s.SpanKind()),
		StartTimeUnixNano:      uint64(s.StartTime().UnixNano()),
		EndTimeUnixNano:        uint64(s.EndTime().UnixNano()),
		Attributes:             attrsToOTLP(s.Attributes()),
		DroppedAttributesCount: uint32(s.DroppedAttributes()),
		DroppedEventsCount:     uint32(s.DroppedEvents()),
		DroppedLinksCount:      uint32(s.DroppedLinks()),
		Status: &tracepb.Status{
			Message: s.Status().Description,
			Code:    statusCodeToOTLP(s.Status().Code),
		},
	}
	if parent := s.Parent(); parent.HasSpanID() {
		parentID := parent.SpanID()
		span.ParentSpanId = parentID[:]
	}
	for _, e := range s.Events() {
		span.Events = append(span.Events, &tracepb.Span_Event{
			TimeUnixNano:           uint64(e.Time.UnixNano()),
			Name:                   e.Name,
			Attributes:             attrsToOTLP(e.Attributes),
			DroppedAttributesCount: uint32(e.DroppedAttributeCount),
		})
	}
	for _, l := range s.Links() {
		lTraceID := l.SpanContext.TraceID()
		lSpanID := l.SpanContext.SpanID()
		span.Links = append(span.Links, &tracepb.Span_Link{
			TraceId:                lTraceID[:],
			SpanId:                 lSpanID[:],
			TraceState:             l.SpanContext.TraceState().String(),
			Attributes:             attrsToOTLP(l.Attributes),
			DroppedAttributesCount: uint32(l.DroppedAttributeCount),
		})
	}
	return span
}

func spanKindToOTLP(k oteltrace.SpanKind) tracepb.Span_SpanKind {
	// oteltrace.SpanKind and tracepb.Span_SpanKind share identical
	// numeric values by construction (both mirror the OTel spec's
	// SpanKind enum 0-5) — a direct cast is correct, not coincidental.
	return tracepb.Span_SpanKind(int32(k))
}

func statusCodeToOTLP(c codes.Code) tracepb.Status_StatusCode {
	switch c {
	case codes.Ok:
		return tracepb.Status_STATUS_CODE_OK
	case codes.Error:
		return tracepb.Status_STATUS_CODE_ERROR
	default:
		return tracepb.Status_STATUS_CODE_UNSET
	}
}

func attrsToOTLP(attrs []attribute.KeyValue) []*commonpb.KeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]*commonpb.KeyValue, len(attrs))
	for i, a := range attrs {
		out[i] = &commonpb.KeyValue{Key: string(a.Key), Value: valueToOTLP(a.Value)}
	}
	return out
}

func valueToOTLP(v attribute.Value) *commonpb.AnyValue {
	switch v.Type() {
	case attribute.BOOL:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: v.AsBool()}}
	case attribute.INT64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v.AsInt64()}}
	case attribute.FLOAT64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: v.AsFloat64()}}
	case attribute.STRING:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v.AsString()}}
	case attribute.BOOLSLICE:
		vals := v.AsBoolSlice()
		arr := make([]*commonpb.AnyValue, len(vals))
		for i, b := range vals {
			arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: b}}
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: arr}}}
	case attribute.INT64SLICE:
		vals := v.AsInt64Slice()
		arr := make([]*commonpb.AnyValue, len(vals))
		for i, n := range vals {
			arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: n}}
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: arr}}}
	case attribute.FLOAT64SLICE:
		vals := v.AsFloat64Slice()
		arr := make([]*commonpb.AnyValue, len(vals))
		for i, f := range vals {
			arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}}
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: arr}}}
	case attribute.STRINGSLICE:
		vals := v.AsStringSlice()
		arr := make([]*commonpb.AnyValue, len(vals))
		for i, s := range vals {
			arr[i] = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: arr}}}
	default:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v.String()}}
	}
}

// marshalOTLPJSON renders req (an ExportTraceServiceRequest) as a single
// line of real OTLP-JSON — protojson, not encoding/json, since the wire
// format's field names/casing/oneof encoding are protobuf-JSON-mapping
// specific, not derivable from the Go struct tags alone.
func marshalOTLPJSON(req proto.Message) ([]byte, error) {
	return protojson.Marshal(req)
}

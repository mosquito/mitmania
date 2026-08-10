package telemetry

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
)

var traceContextPropagator = propagation.TraceContext{}

// InjectAlways writes the current span's W3C traceparent into header —
// for mitmania's OWN dependencies (outcall broker calls; s3:// Storage
// calls), which always carry it regardless of --otel-propagate-
// upstream: correlating their latency with our trace is the whole point
// of tracing them at all, and neither is client traffic passing through
// us that would be mutated by the injection.
func InjectAlways(ctx context.Context, header http.Header) {
	traceContextPropagator.Inject(ctx, propagation.HeaderCarrier(header))
}

// InjectUpstream writes traceparent into header only when enabled
// (--otel-propagate-upstream) — stealth by default: injecting into a
// forwarded client request would mutate the client's own traffic and
// reveal the proxy's presence, the same "never announce the proxy"
// posture as cert cloning (leaf certs mirror the origin's real
// certificate) and the root CA's generic, non-identifying Subject.
func InjectUpstream(ctx context.Context, header http.Header, enabled bool) {
	if !enabled {
		return
	}
	InjectAlways(ctx, header)
}

// ExtractClient parses a client-supplied traceparent from header into ctx
// only when enabled (--otel-continue-client) — otherwise ctx is returned
// unchanged, so the next span started from it becomes a fresh root: a
// client shouldn't be able to drive our trace ids or sampling decision by
// default.
func ExtractClient(ctx context.Context, header http.Header, enabled bool) context.Context {
	if !enabled {
		return ctx
	}
	return traceContextPropagator.Extract(ctx, propagation.HeaderCarrier(header))
}

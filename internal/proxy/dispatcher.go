package proxy

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/session"
	"mitmania/internal/telemetry"
)

// Dispatcher is the transport-agnostic pipeline: an Acceptor hands it
// a Session, it picks a handler via Selector and runs it. Dispatcher never
// terminates TLS itself — the handler drives TLSService on demand.
type Dispatcher struct {
	Selector *Selector
	Dialer   UpstreamDialer

	// Metrics and Tracer back the connection-level telemetry signals: one root
	// span per connection (child spans are started further down the
	// pipeline, correlated via the ctx this handler receives) and the
	// connections.active/.total metrics. Both nil-safe — see Metrics' own
	// doc comment and trace.Tracer's documented nil/noop behavior — so
	// Dispatcher works unconfigured exactly as before telemetry existed.
	Metrics *telemetry.Metrics
	Tracer  trace.Tracer
}

// Handle starts the root span + connection-open/close accounting for sess,
// then hands off to the selected ProtocolHandler with a ctx carrying that
// span — every child span the handler starts (request, upstream dial, TLS
// handshake, cert mint, outcall, storage op) nests under it.
func (d *Dispatcher) Handle(ctx context.Context, sess session.Session) {
	listener := sess.Acceptor
	transport := sess.Transport.String()

	d.Metrics.ConnectionOpened(ctx, listener, transport)
	defer d.Metrics.ConnectionClosed(ctx, listener, transport)

	if d.Tracer != nil {
		var span trace.Span
		ctx, span = d.Tracer.Start(ctx, "connection", trace.WithAttributes(
			attribute.String("client", sess.ClientKey().String()),
			attribute.String("listener", listener),
			attribute.String("transport", transport),
		))
		defer span.End()
	}

	d.Selector.Pick(sess).Serve(ctx, sess, d.Dialer)
}

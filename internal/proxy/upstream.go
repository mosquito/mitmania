package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/telemetry"
)

// UpstreamDialer establishes connections to the real origin: DialTLS for
// the CONNECT/MITM path (TLSService fetches the real certificate chain
// over it), Dial for plain absolute-form HTTP proxying.
type UpstreamDialer interface {
	DialTLS(ctx context.Context, network, addr, serverName string) (*tls.Conn, error)
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTLSH1Only is DialTLS but forces http/1.1 in the ALPN offer (never
	// h2) — for requests that need real h1 wire semantics h2 structurally
	// can't provide: a WebSocket Upgrade request forwarded over h2 fails
	// outright (RFC 9113 §8.5 forbids the Upgrade header; WS-over-h2 would
	// need RFC 8441 extended CONNECT, a different, unimplemented
	// mechanism), so h2RoundTripper falls back to a dedicated connection
	// dialed this way instead of using the shared upstream connection.
	DialTLSH1Only(ctx context.Context, network, addr, serverName string) (*tls.Conn, error)
	// LookupIP resolves host to its addresses for the egress-policy
	// resolve-phase — a seam separate from Dial/DialTLS so that phase can
	// pin one policy-approved address before any dial happens at all, and
	// so tests can mock resolution independent of connectivity.
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// netDialer is the default UpstreamDialer, backed by net.Dialer.
type netDialer struct {
	d net.Dialer

	// ConnectTimeout bounds each individual dial attempt (TCP+TLS for
	// DialTLS); ConnectTries is how many attempts withRetries makes before
	// giving up (--http-timeout-connect / --http-connect-tries).
	ConnectTimeout time.Duration
	ConnectTries   int

	log *slog.Logger // nil disables per-attempt logging (WithDialerLogger)

	// metrics/tracer back the upstream.dials.total/dial.duration and
	// tls.handshake.duration (leg=upstream), plus an "upstream.dial"
	// child span — nil-safe, same convention as log.
	metrics *telemetry.Metrics
	tracer  trace.Tracer
}

// DialerOption configures NewUpstreamDialer.
type DialerOption func(*netDialer)

// WithDialerLogger enables Debug-level logging of every dial attempt
// (including retries) — nil (the default) disables it, same convention
// as Http1Handler.Logger.
func WithDialerLogger(log *slog.Logger) DialerOption {
	return func(d *netDialer) { d.log = log }
}

// WithDialerMetrics enables the upstream.dials.total/dial.duration
// and tls.handshake.duration (leg=upstream) metrics — nil (the default)
// leaves them unrecorded.
func WithDialerMetrics(m *telemetry.Metrics) DialerOption {
	return func(d *netDialer) { d.metrics = m }
}

// WithDialerTracer enables an "upstream.dial" child span per dial —
// nil (the default) leaves tracing off.
func WithDialerTracer(t trace.Tracer) DialerOption {
	return func(d *netDialer) { d.tracer = t }
}

// NewUpstreamDialer returns the default net.Dialer-backed UpstreamDialer.
// connectTimeout bounds each dial attempt; connectTries is how many
// attempts are made before giving up.
func NewUpstreamDialer(connectTimeout time.Duration, connectTries int, opts ...DialerOption) UpstreamDialer {
	d := &netDialer{ConnectTimeout: connectTimeout, ConnectTries: connectTries}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (u *netDialer) DialTLS(ctx context.Context, network, addr, serverName string) (*tls.Conn, error) {
	// NextProtos always offers both h2 and http/1.1 (never omitted: a
	// ClientHello with no ALPN extension at all is itself an anomaly real
	// browsers never produce, and some upstreams use exactly that kind of
	// signal for bot/proxy detection). Which one is actually negotiated
	// drives whether the client-facing leg offers h2 too — see
	// TLSService.Terminate.
	return u.dialTLS(ctx, network, addr, serverName, []string{"h2", "http/1.1"})
}

func (u *netDialer) DialTLSH1Only(ctx context.Context, network, addr, serverName string) (*tls.Conn, error) {
	return u.dialTLS(ctx, network, addr, serverName, []string{"http/1.1"})
}

func (u *netDialer) dialTLS(ctx context.Context, network, addr, serverName string, nextProtos []string) (*tls.Conn, error) {
	var span trace.Span
	if u.tracer != nil {
		ctx, span = u.tracer.Start(ctx, "upstream.dial", trace.WithAttributes(attribute.String("addr", addr), attribute.String("sni", serverName)))
		defer span.End()
	}
	start := time.Now()

	conn, err := withRetries(ctx, u.log, "dial_tls "+addr, u.ConnectTries, u.ConnectTimeout, func(attemptCtx context.Context) (*tls.Conn, error) {
		rawConn, err := u.d.DialContext(attemptCtx, network, addr)
		if err != nil {
			return nil, err
		}
		// Deliberately not validating upstream trust: cert cloning wants an
		// expired/mismatched-upstream cert reproduced faithfully for the
		// proxied client, not rejected here before it can even be cloned.
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         nextProtos,
		})
		hsStart := time.Now()
		hsErr := tlsConn.HandshakeContext(attemptCtx)
		hsResult := "ok"
		if hsErr != nil {
			hsResult = "tls"
		}
		u.metrics.TLSHandshake(attemptCtx, "upstream", hsResult, time.Since(hsStart))
		if hsErr != nil {
			rawConn.Close()
			return nil, hsErr
		}
		return tlsConn, nil
	})

	proto, result := "unknown", dialResultLabel(err)
	if err == nil {
		proto = negotiatedProto(conn)
	}
	u.metrics.UpstreamDial(ctx, proto, result, time.Since(start))
	if span != nil && err != nil {
		span.RecordError(err)
	}
	return conn, err
}

func (u *netDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var span trace.Span
	if u.tracer != nil {
		ctx, span = u.tracer.Start(ctx, "upstream.dial", trace.WithAttributes(attribute.String("addr", addr)))
		defer span.End()
	}
	start := time.Now()

	conn, err := withRetries(ctx, u.log, "dial "+addr, u.ConnectTries, u.ConnectTimeout, func(attemptCtx context.Context) (net.Conn, error) {
		return u.d.DialContext(attemptCtx, network, addr)
	})

	u.metrics.UpstreamDial(ctx, "h1", dialResultLabel(err), time.Since(start))
	if span != nil && err != nil {
		span.RecordError(err)
	}
	return conn, err
}

// dialResultLabel classifies a TCP-dial-phase failure into the
// upstream.dials.total/dial.duration result vocabulary (ok/dns/timeout/
// refused) — "tls" is reserved for TLS-handshake-phase failures, recorded
// separately at that call site (a handshake only runs once the TCP dial
// already succeeded, so any failure there is unambiguously a TLS problem,
// no classifier needed).
func dialResultLabel(err error) string {
	if err == nil {
		return "ok"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns"
	}
	if isTimeout(err) {
		return "timeout"
	}
	return "refused"
}

// negotiatedProto maps a successful DialTLS's ALPN result to the
// proto label (h1/h2) — no negotiated protocol (or anything other than
// "h2") means the connection speaks HTTP/1.1.
func negotiatedProto(conn *tls.Conn) string {
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		return "h2"
	}
	return "h1"
}

func (u *netDialer) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if u.log != nil {
			u.log.Debug("dns lookup failed", "host", host, "err", err.Error())
		}
		return nil, err
	}
	addrs := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.Unmap()
	}
	if u.log != nil {
		u.log.Debug("dns lookup", "host", host, "addrs", addrs)
	}
	return addrs, nil
}

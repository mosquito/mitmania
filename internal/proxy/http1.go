package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/flowsink"
	"mitmania/internal/httperror"
	"mitmania/internal/outcall"
	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/telemetry"
)

// bufioReadSize is the bufio.Reader buffer size used while parsing
// request/response headers — independent of HeaderLimit (which bounds
// total bytes read via the wrapping io.LimitedReader), just a reasonable
// I/O chunk size.
const bufioReadSize = 4096

// Http1Handler is the v1 ProtocolHandler: it demuxes CONNECT,
// absolute-form, and the self-directed GET /ca.pem, applies the per-client
// rule engine, and relays HTTP/1.1 traffic.
type Http1Handler struct {
	TLS   *TLSService
	Rules *rules.RuleEngine
	Flow  flowsink.FlowSink // nil is fine: telemetry is best-effort, never load-bearing
	CAPEM []byte            // served at GET /ca.pem; nil disables the self-directed endpoint

	// Outcall backs the webhook/header.fetch actions. nil means
	// no OutcallService is configured — a rule using either action then
	// fails closed (unless the action's own failOpen says otherwise),
	// same as a broker that's actually unreachable.
	Outcall *outcall.Service

	// Logger, if set, receives one structured access-log record per
	// request/tunnel (client, method, URL, outcome, status, latency) —
	// never the cluster key or rule/secret content, just what's needed to
	// see what the proxy did — plus the upstream roundtrippers' own
	// dial/reconnect debug logging, which is NOT access logging
	// and stays on even when NoAccessLog is set. nil disables everything
	// this handler and its roundtrippers log.
	Logger *slog.Logger

	// NoAccessLog disables just the per-request/per-tunnel access record
	// (--no-access-logs) — a volume knob for the one record type that's
	// genuinely one-per-request, independent of Logger being set (which
	// upstream dial/reconnect logging still needs).
	NoAccessLog bool

	// HeaderLimit and BodyWindow are Http1Handler's own framing bounds.
	// BodyWindow is unused: no match field in this pass inspects
	// body content, so there's nothing to tee a window of yet (only
	// body.replace exists, which discards the original body outright).
	HeaderLimit int
	BodyWindow  int

	// ReadTimeout bounds how long h1 waits for the upstream response to
	// start (headers) — set as a read deadline before http.ReadResponse,
	// cleared before streaming the body so a slow-but-legitimate large
	// download doesn't time out (--http-timeout-read).
	ReadTimeout time.Duration

	// HTTP2ConnectTimeout/HTTP2ConnectTries bound the upstream h2
	// preface/SETTINGS exchange (--http2-timeout-connect,
	// --http2-connect-tries); HTTP2ReadTimeout is h2RoundTripper's
	// per-stream response-header wait (--http2-timeout-read).
	HTTP2ConnectTimeout time.Duration
	HTTP2ConnectTries   int
	HTTP2ReadTimeout    time.Duration

	// Metrics/Tracer back the request.duration/requests.total metrics
	// and the "request" child span (one per request/CONNECT-tunnel) —
	// nil-safe, same convention as Logger.
	Metrics *telemetry.Metrics
	Tracer  trace.Tracer

	// TrustedProxies backs client-IP recovery: peers in this set
	// have their X-Forwarded-For/X-Real-IP honored to recover the real
	// client IP behind a SNAT load balancer. nil/empty disables recovery
	// entirely — Session.Client (the raw peer) is always used, matching
	// today's behavior.
	TrustedProxies []netip.Prefix
}

// reqTrace bundles what a request/tunnel's logAccess/logAccessErr calls
// need to close out both the access-log record and the request
// span+metric — created once per request/tunnel (startReq) alongside
// what used to be a bare "start time.Time", and threaded through
// unchanged exactly the same way start was before telemetry existed.
type reqTrace struct {
	start time.Time
	span  trace.Span
	proto string

	// dst is the resolved upstream literal address (ip:port, v4 or v6 —
	// resolveAndPin's pinned result), set by the caller once known
	// (a request/tunnel's dst is only known partway through, after the
	// resolve-phase, so this can't be filled in at startReq time). Empty
	// until set — logAccessErr omits it entirely rather than logging a
	// blank field for the early-failure paths that never reach a dial
	// (invalid request, no-match, forwarding-denied before resolve, …).
	dst string

	// principal is the auth.http_proxy-authenticated identity, set
	// by checkAuth once known. Empty when auth isn't configured/required,
	// or hasn't succeeded yet — logAccessErr omits it entirely rather
	// than logging a blank field, same convention as dst.
	principal string
}

// withDst records dst (already resolved/pinned — resolveAndPin's literal
// ip:port, v4 or v6) onto rt for logAccessErr and the request span to
// pick up — called once a request/tunnel's upstream address is actually
// known. rt is a value type threaded by the caller's own local variable,
// so this mutates that copy directly; every logAccess/logAccessErr call
// after this point using the same variable sees it.
func (rt *reqTrace) withDst(dst string) {
	rt.dst = dst
	if rt.span != nil {
		rt.span.SetAttributes(attribute.String("dst", dst))
	}
}

// withPrincipal records the auth.http_proxy-authenticated principal onto
// rt, same mutation convention as withDst.
func (rt *reqTrace) withPrincipal(principal string) {
	rt.principal = principal
	if rt.span != nil {
		rt.span.SetAttributes(attribute.String("principal", principal))
	}
}

// startReq begins a request/tunnel's timing and (if h.Tracer is set) span,
// returning the context any child spans further down this request's
// handling should use, plus the reqTrace value to thread through to
// logAccess/logAccessErr. method/url may be empty when not yet known
// (e.g. before the request line has even parsed) — the span still starts,
// just without those attributes.
func (h *Http1Handler) startReq(ctx context.Context, proto, method, url string) (context.Context, reqTrace) {
	rt := reqTrace{start: time.Now(), proto: proto}
	if h.Tracer != nil {
		attrs := []attribute.KeyValue{attribute.String("proto", proto)}
		if method != "" {
			attrs = append(attrs, attribute.String("method", method))
		}
		if url != "" {
			attrs = append(attrs, attribute.String("url", url))
		}
		ctx, rt.span = h.Tracer.Start(ctx, "request", trace.WithAttributes(attrs...))
	}
	return ctx, rt
}

// logAccess writes one access-log record if a Logger is configured, plus
// the request metric/span regardless (independent of NoAccessLog,
// same as every other metrics/span call site in this codebase). status is
// 0 when there's no HTTP status to report (e.g. a raw splice or a
// connection reset).
func (h *Http1Handler) logAccess(sess session.Session, method, url, outcome string, status int, rt reqTrace) {
	h.logAccessErr(sess, method, url, outcome, status, rt, nil)
}

// logAccessErr is logAccess plus the underlying Go error that produced a
// failure outcome (upstream dial/write/read errors, TLS handshake
// failures, etc.) — without this, every upstream failure collapses to the
// same opaque outcome string with no way to tell "connection refused" from
// "TLS handshake failed" from "context deadline exceeded" apart. err is
// omitted from the record when nil.
func (h *Http1Handler) logAccessErr(sess session.Session, method, url, outcome string, status int, rt reqTrace, err error) {
	elapsed := time.Since(rt.start)

	if h.Logger != nil && !h.NoAccessLog {
		attrs := []any{
			slog.String("client", sess.ClientKey().String()),
			slog.String("acceptor", sess.Acceptor),
			slog.String("method", method),
			slog.String("url", url),
			slog.String("outcome", outcome),
			slog.Duration("elapsed", elapsed),
		}
		if rt.dst != "" {
			attrs = append(attrs, slog.String("dst", rt.dst))
		}
		if rt.principal != "" {
			attrs = append(attrs, slog.String("principal", rt.principal))
		}
		if status != 0 {
			attrs = append(attrs, slog.Int("status", status))
		}
		if err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		h.Logger.Info("access", attrs...)
	}

	h.Metrics.Request(context.Background(), rt.proto, outcome, statusClass(status), elapsed)
	if rt.span != nil {
		rt.span.SetAttributes(attribute.String("outcome", outcome))
		if status != 0 {
			rt.span.SetAttributes(attribute.Int("status", status))
		}
		if err != nil {
			rt.span.RecordError(err)
		}
		rt.span.End()
	}
}

// statusClass maps an HTTP status to the low-cardinality
// requests.total label ("2xx".."5xx"); status == 0 (no HTTP status at
// all, e.g. a raw splice) maps to "" rather than a misleading "0xx".
func statusClass(status int) string {
	if status == 0 {
		return ""
	}
	return strconv.Itoa(status/100) + "xx"
}

// requestURL reconstructs a full URL for logging from what's known at
// connection-phase plus the parsed request — req.URL alone is origin-form
// (path only) once inside a CONNECT tunnel or after absolute-form
// normalization.
func requestURL(connIn rules.ConnInput, req *http.Request) string {
	host := req.Host
	if host == "" {
		host = connIn.Host
	}
	return connIn.Proto + "://" + host + req.URL.RequestURI()
}

func (h *Http1Handler) Serve(ctx context.Context, sess session.Session, dialer UpstreamDialer) {
	defer sess.Conn.Close()
	if h.Flow != nil {
		h.Flow.ConnAccepted()
		defer h.Flow.ConnClosed()
	}

	ctx, treq := h.startReq(ctx, "h1", "", "")
	stream := newPrependConn(sess.Conn)
	sess.Conn = stream
	br := bufio.NewReaderSize(stream, bufioReadSize)
	req, err := h.readBoundedRequest(sess, stream, br, treq)
	if err != nil {
		return // readBoundedRequest already logged+ended treq's span on failure
	}
	if treq.span != nil {
		// Parsing succeeded; the actual request/tunnel gets its own,
		// more specific span below (serveConnect/serveAbsoluteForm) —
		// this one only ever covered the parse phase.
		treq.span.End()
	}

	if len(h.TrustedProxies) > 0 && sess.Client.IsValid() {
		recovered := recoverClientIP(sess.Client.Addr(), req.Header, h.TrustedProxies)
		sess.Client = netip.AddrPortFrom(recovered, sess.Client.Port())
	}

	switch {
	case req.Method == http.MethodConnect:
		h.serveConnect(ctx, sess, br, req, dialer)
	case req.URL.IsAbs():
		h.serveAbsoluteForm(ctx, sess, br, req, dialer)
	case req.Method == http.MethodGet && req.URL.Path == "/ca.pem":
		writeCAPEM(sess.Conn, h.CAPEM)
	default:
		httperror.WriteResponse(sess.Conn, req.URL.String(), httperror.InvalidRequest)
		h.logAccess(sess, req.Method, req.URL.String(), "invalid-request-shape", httperror.InvalidRequest.Status, treq)
	}
}

// readBoundedRequest parses the request line and headers within
// HeaderLimit bytes. A limit violation is reported as 431; any
// other parse failure as 400. Neither has a real request URL to attribute
// the Squid page to yet (parsing failed before one exists), so an empty
// URL is rendered instead.
func (h *Http1Handler) readBoundedRequest(sess session.Session, conn *prependConn, br *bufio.Reader, treq reqTrace) (*http.Request, error) {
	err := boundNextHeaderBlock(br, conn, h.HeaderLimit)
	if err != nil {
		spec := httperror.InvalidRequest
		outcome := "invalid-request"
		if errors.Is(err, errHeadersTooLarge) {
			spec = httperror.HeadersTooLarge
			outcome = "headers-too-large"
		}
		httperror.WriteResponse(conn, "", spec)
		h.logAccessErr(sess, "", "", outcome, spec.Status, treq, err)
		return nil, err
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		httperror.WriteResponse(conn, "", httperror.InvalidRequest)
		h.logAccessErr(sess, "", "", "invalid-request", httperror.InvalidRequest.Status, treq, err)
		return nil, err
	}
	return req, nil
}

func (h *Http1Handler) serveConnect(ctx context.Context, sess session.Session, br *bufio.Reader, req *http.Request, dialer UpstreamDialer) {
	ctx, treq := h.startReq(ctx, "h1", http.MethodConnect, req.Host)
	conn := sess.Conn
	host, port, dst, err := normalizeAuthority(req.Host, "443")
	if err != nil {
		httperror.WriteResponse(conn, req.Host, httperror.InvalidRequest)
		h.logAccessErr(sess, http.MethodConnect, req.Host, "invalid-connect-authority", httperror.InvalidRequest.Status, treq, err)
		return
	}
	reqURL := "https://" + dst
	connIn := rules.ConnInput{Host: host, Port: port, Proto: "https"}

	// Fail closed before making any network connection. Without this
	// connection-phase check, even a client with an empty ruleset could use
	// CONNECT responses as an internal port scanner because the reachability
	// probe below ran before policy evaluation.
	ruleSet, err := h.Rules.Lookup(ctx, sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, http.MethodConnect, reqURL, "rule-engine-error", 0, treq, err)
		return
	}

	// auth.http_proxy runs before the connection-phase rule match,
	// right here. checkAuth has already written the 407/403 response and
	// logged on failure; on success it never changes which ruleSet
	// governs the connection (mitmania is a data-plane, rule
	// selection is a pure function of source address).
	principal, authOK := h.checkAuth(ctx, sess, ruleSet, req, reqURL, treq)
	if !authOK {
		return
	}
	if principal != "" {
		treq.withPrincipal(principal)
	}

	mitm, matched := ruleSet.LookupConn(connIn)
	if !matched {
		httperror.WriteResponse(conn, reqURL, httperror.NoMatch)
		h.logAccess(sess, http.MethodConnect, reqURL, "no-match", httperror.NoMatch.Status, treq)
		return
	}

	// Egress-policy resolve-phase: resolve once, check every returned address
	// against egress policy, and pin dst to one approved literal address
	// so nothing dialed for the rest of this connection (probe below,
	// TLSService.Terminate, h1/h2 redials, the mitm:false splice) ever
	// re-resolves the name. "http" is the L7 handler name (this proxy has
	// only ever the one), distinct from connIn.Proto's http/https
	// transport distinction.
	pinned, err := resolveAndPin(ctx, ruleSet, dialer, host, port, "http")
	if err != nil {
		var denied *egressDeniedError
		if errors.As(err, &denied) {
			httperror.WriteResponse(conn, reqURL, httperror.ForwardingDenied)
			h.logAccessErr(sess, http.MethodConnect, reqURL, "forwarding-denied", httperror.ForwardingDenied.Status, treq, err)
			return
		}
		spec := classifyConnectErr(err)
		httperror.WriteResponse(conn, reqURL, spec)
		h.logAccessErr(sess, http.MethodConnect, reqURL, "resolve-fail", spec.Status, treq, err)
		return
	}
	dst = pinned
	treq.withDst(dst)

	// The "Explicit, pre-tunnel" error-delivery mechanic: a connect-phase
	// upstream failure can still go in the CONNECT response itself
	// (non-200), before any TLS starts on either leg — so probe
	// reachability with a plain TCP dial first, while there's still a
	// clean HTTP response channel to report it on, instead of a silent
	// drop after "200 Connection Established". This dial is safe only
	// because the CONNECT authority was authorized above. Closed
	// immediately: it's a reachability check only, not reused, so a
	// mitm:false raw splice always gets a fully untouched connection.
	probe, err := dialer.Dial(ctx, "tcp", dst)
	if err != nil {
		spec := classifyConnectErr(err)
		httperror.WriteResponse(conn, reqURL, spec)
		h.logAccessErr(sess, http.MethodConnect, reqURL, "connect-fail", spec.Status, treq, err)
		return
	}
	probe.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	tunnel := drainBuffered(br, conn)
	if !mitm {
		h.logAccess(sess, http.MethodConnect, reqURL, "splice (mitm:false)", 0, treq)
		rawSplice(ctx, tunnel, dialer, dst)
		return
	}

	hello, err := PeekClientHello(tunnel)
	if err != nil {
		h.logAccessErr(sess, http.MethodConnect, reqURL, "peek-error", 0, treq, err)
		return
	}

	sni := hello.ServerName
	if sni == "" {
		sni = host
	}

	replayed := Replay(tunnel, hello.Raw)
	if !sameHost(sni, host) {
		err := fmt.Errorf("CONNECT host %q does not match TLS SNI %q", host, sni)
		if ferr := h.TLS.Fallback(ctx, replayed, sni, reqURL, httperror.MisdirectedRequest); ferr != nil {
			h.logAccessErr(sess, http.MethodConnect, reqURL, "sni-mismatch-fallback-failed", 0, treq, ferr)
			return
		}
		h.logAccessErr(sess, http.MethodConnect, reqURL, "sni-mismatch", httperror.MisdirectedRequest.Status, treq, err)
		return
	}

	result, err := h.TLS.Terminate(ctx, replayed, dialer, dst, sni)
	if err != nil {
		h.terminateFailed(ctx, sess, replayed, sni, reqURL, treq, err)
		return
	}

	// ALPN plumbing: h2 is only ever offered to the client when the one
	// upstream connection dialed for this session also negotiated h2 (see
	// TLSService.Terminate) — so result.ALPN == "h2" implies
	// result.UpstreamALPN == "h2" too, and serveH2 owns both legs.
	if result.ALPN == "h2" {
		if treq.span != nil {
			treq.span.End() // request/tunnel is handed off; serveH2 owns its own per-stream spans from here
		}
		h.serveH2(ctx, sess, dialer, result.Client, result.Upstream, dst, sni, connIn, principal)
		return
	}

	if result.UpstreamALPN == "h2" {
		cc, upConn, err := newUpstreamH2ClientConn(ctx, dialer, h.Logger, dst, sni, h.HTTP2ConnectTries, h.HTTP2ConnectTimeout, h.HeaderLimit, result.Upstream)
		if err != nil {
			// Unlike a Terminate failure, the client's real handshake has
			// already succeeded at this point (result.Client, cert cloned
			// normally from the real chain fetched above) — no fallback
			// cert needed, just serve the page directly over the session
			// that's already there.
			spec := classifyTerminateDialErr(err)
			httperror.WriteResponse(result.Client, reqURL, spec)
			result.Client.Close()
			h.logAccessErr(sess, http.MethodConnect, reqURL, "h2-connect-fail", spec.Status, treq, err)
			return
		}
		roundTripper := &h2RoundTripper{dialer: dialer, dst: dst, sni: sni, connectTimeout: h.HTTP2ConnectTimeout, connectTries: h.HTTP2ConnectTries, maxHeaderListSize: h.HeaderLimit, readTimeout: h.HTTP2ReadTimeout, log: h.Logger, metrics: h.Metrics, tracer: h.Tracer}
		roundTripper.seed(cc, upConn)
		if treq.span != nil {
			treq.span.End() // request/tunnel is handed off; relayIntercepted starts its own per-request spans from here
		}
		h.relayIntercepted(ctx, sess, result.Client, roundTripper, roundTripper, connIn, dst, nil, nil, principal)
		return
	}

	redial := func(redialCtx context.Context) (net.Conn, error) {
		return dialer.DialTLS(redialCtx, "tcp", dst, sni)
	}
	roundTripper := newH1RoundTripper(result.Upstream, h.ReadTimeout, h.HeaderLimit, redial, h.Logger, h.Metrics, h.Tracer)
	if treq.span != nil {
		treq.span.End() // request/tunnel is handed off; relayIntercepted starts its own per-request spans from here
	}
	h.relayIntercepted(ctx, sess, result.Client, roundTripper, roundTripper, connIn, dst, nil, nil, principal)
}

// terminateFailed handles a TLSService.Terminate failure (the
// "Over-TLS" error-delivery mechanic): a PhaseDial or PhaseMint failure happens before
// the client's real handshake is ever attempted, so clientConn is still
// pristine — safe to complete a fallback handshake (synthetic leaf, no
// real chain to clone) and serve the Squid-style page over it instead of
// silently dropping. A PhaseHandshake failure means the client's own
// handshake attempt with us already failed, so its TLS state may be
// desynced — nothing further is attempted, matching today's behavior.
func (h *Http1Handler) terminateFailed(ctx context.Context, sess session.Session, clientConn net.Conn, sni, reqURL string, treq reqTrace, err error) {
	var terr *TerminateError
	if !errors.As(err, &terr) || terr.Phase == PhaseHandshake {
		h.logAccessErr(sess, http.MethodConnect, reqURL, "tls-terminate-error", 0, treq, err)
		return
	}

	spec := httperror.InternalError
	if terr.Phase == PhaseDial {
		spec = classifyTerminateDialErr(terr)
	}
	if ferr := h.TLS.Fallback(ctx, clientConn, sni, reqURL, spec); ferr != nil {
		h.logAccessErr(sess, http.MethodConnect, reqURL, "fallback-failed", 0, treq, ferr)
		return
	}
	h.logAccessErr(sess, http.MethodConnect, reqURL, "fallback-served", spec.Status, treq, err)
}

func (h *Http1Handler) serveAbsoluteForm(ctx context.Context, sess session.Session, br *bufio.Reader, req *http.Request, dialer UpstreamDialer) {
	ctx, treq := h.startReq(ctx, "h1", req.Method, req.URL.String())
	conn := sess.Conn
	if !strings.EqualFold(req.URL.Scheme, "http") {
		httperror.WriteResponse(conn, req.URL.String(), httperror.InvalidRequest)
		h.logAccess(sess, req.Method, req.URL.String(), "unsupported-absolute-scheme", httperror.InvalidRequest.Status, treq)
		return
	}
	host, port, dst, err := normalizeAuthority(req.URL.Host, "80")
	if err != nil {
		httperror.WriteResponse(conn, req.URL.String(), httperror.InvalidRequest)
		h.logAccessErr(sess, req.Method, req.URL.String(), "invalid-request-authority", httperror.InvalidRequest.Status, treq, err)
		return
	}
	connIn := rules.ConnInput{Host: host, Port: port, Proto: "http"}

	// As with CONNECT, authorization must precede Dial. A denied absolute-
	// form request must not still create a TCP connection to its target.
	ruleSet, err := h.Rules.Lookup(ctx, sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, req.Method, req.URL.String(), "rule-engine-error", 0, treq, err)
		return
	}

	// Same auth.http_proxy gate as serveConnect, run here since absolute-form
	// has no separate pre-tunnel phase of its own.
	principal, authOK := h.checkAuth(ctx, sess, ruleSet, req, req.URL.String(), treq)
	if !authOK {
		return
	}
	if principal != "" {
		treq.withPrincipal(principal)
	}
	// Proxy-Authorization is hop-by-hop — consumed above, never
	// forwarded upstream, regardless of whether auth was even configured.
	req.Header.Del("Proxy-Authorization")

	if _, matched := ruleSet.LookupConn(connIn); !matched {
		httperror.WriteResponse(conn, req.URL.String(), httperror.NoMatch)
		h.logAccess(sess, req.Method, req.URL.String(), "no-match", httperror.NoMatch.Status, treq)
		return
	}

	// Egress-policy resolve-phase, same as serveConnect: pin dst to one
	// egress-approved literal address before any dial.
	pinned, err := resolveAndPin(ctx, ruleSet, dialer, host, port, "http")
	if err != nil {
		var denied *egressDeniedError
		if errors.As(err, &denied) {
			httperror.WriteResponse(conn, req.URL.String(), httperror.ForwardingDenied)
			h.logAccessErr(sess, req.Method, req.URL.String(), "forwarding-denied", httperror.ForwardingDenied.Status, treq, err)
			return
		}
		spec := classifyConnectErr(err)
		httperror.WriteResponse(conn, req.URL.String(), spec)
		h.logAccessErr(sess, req.Method, req.URL.String(), "resolve-fail", spec.Status, treq, err)
		return
	}
	dst = pinned
	treq.withDst(dst)

	upstream, err := dialer.Dial(ctx, "tcp", dst)
	if err != nil {
		spec := classifyConnectErr(err)
		httperror.WriteResponse(conn, req.URL.String(), spec)
		h.logAccessErr(sess, req.Method, req.URL.String(), "connect-fail", spec.Status, treq, err)
		return
	}

	// RFC 7230 §5.3: a proxy forwards an absolute-form request to its
	// origin in origin-form. Clearing Scheme/Host makes URL.RequestURI()
	// produce a relative target; req.Host (already populated) still drives
	// the Host header.
	req.URL.Scheme = ""
	req.URL.Host = ""

	redial := func(redialCtx context.Context) (net.Conn, error) {
		return dialer.Dial(redialCtx, "tcp", dst)
	}
	roundTripper := newH1RoundTripper(upstream, h.ReadTimeout, h.HeaderLimit, redial, h.Logger, h.Metrics, h.Tracer)
	if treq.span != nil {
		treq.span.End() // request is handed off; relayIntercepted starts its own per-request spans from here
	}
	h.relayIntercepted(ctx, sess, conn, roundTripper, roundTripper, connIn, dst, req, br, principal)
}

// relayIntercepted is the message-phase loop: for each
// request on the connection (firstReq/firstBR let a caller that already
// parsed the first one — absolute-form — feed it in directly), look up
// the winning rule, apply its request[] pipeline, forward, apply the
// winning rule's response[] pipeline, and relay the (possibly mutated)
// response. No match -> 511; raise -> its Squid page; block -> reset with
// no page. Continues across keep-alive requests until either side
// closes or a rule/response says otherwise.
// relayIntercepted's upstream leg is expressed as http.RoundTripper so the
// same client-facing h1 read/apply/write loop works whether upstream
// negotiated h1 (raw conn) or h2 (*http2.ClientConn) — see roundtrip.go.
// upstreamCloser releases whatever upstream actually is when the connection
// ends (a *tls.Conn/net.Conn either way, since http.RoundTripper itself
// has no Close method).
func (h *Http1Handler) relayIntercepted(ctx context.Context, sess session.Session, client net.Conn, upstream http.RoundTripper, upstreamCloser io.Closer, connIn rules.ConnInput, dst string, firstReq *http.Request, firstBR *bufio.Reader, principal string) {
	stream, ok := client.(*prependConn)
	if !ok {
		stream = newPrependConn(client)
		client = stream
	}
	defer client.Close()
	defer upstreamCloser.Close()

	clientBR := firstBR
	if clientBR == nil {
		clientBR = bufio.NewReaderSize(stream, bufioReadSize)
	}

	req := firstReq
	for {
		if req == nil {
			var err error
			// proto/method/url aren't known yet at this point — this span
			// only covers "waiting for the next keep-alive request's
			// headers"; handleOneRequest starts its own, more specific
			// span once req is parsed.
			_, treq := h.startReq(ctx, "h1", "", "")
			req, err = h.readBoundedRequest(sess, stream, clientBR, treq)
			if err != nil {
				return
			}
		}

		if !h.handleOneRequest(ctx, sess, client, upstream, clientBR, connIn, dst, req, principal) {
			return
		}
		req = nil
	}
}

// handleOneRequest processes a single request/response pair. It returns
// false when the connection should end (a rule short-circuited, an error
// occurred, or either side asked to close). It re-resolves the rule set
// via h.Rules.Lookup(ctx, sess.ClientKey()) on every call — the same
// hot-reload-on-every-keep-alive-request behavior as before, just without
// a separate lookup indirection now that checkAuth never changes which
// file governs the connection. principal is checkAuth's
// authenticated identity for this connection (empty when auth isn't
// configured), so every request's own access-log record carries it too,
// not just the CONNECT/absolute-form one.
func (h *Http1Handler) handleOneRequest(ctx context.Context, sess session.Session, client net.Conn, upstream http.RoundTripper, clientBR *bufio.Reader, connIn rules.ConnInput, dst string, req *http.Request, principal string) bool {
	if h.Flow != nil {
		h.Flow.RequestServed()
	}
	url := requestURL(connIn, req)
	proto := "h1"
	if _, ok := upstream.(*h2RoundTripper); ok {
		proto = "h2"
	}
	ctx, treq := h.startReq(ctx, proto, req.Method, url)
	treq.withDst(dst) // already pinned/resolved by the caller (serveConnect/serveAbsoluteForm)
	if principal != "" {
		treq.withPrincipal(principal)
	}
	req = req.WithContext(ctx)

	if !authorityMatches(req.Host, connIn.Host, connIn.Port, connIn.Proto) {
		httperror.WriteResponse(client, req.URL.RequestURI(), httperror.MisdirectedRequest)
		h.logAccess(sess, req.Method, url, "misdirected-authority", httperror.MisdirectedRequest.Status, treq)
		return false
	}

	ruleSet, err := h.Rules.Lookup(req.Context(), sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, req.Method, url, "rule-engine-error", 0, treq, err)
		return false
	}

	msgIn := rules.MsgInput{ConnInput: connIn, Path: req.URL.Path, Method: req.Method, Header: req.Header}
	rule, matched := ruleSet.LookupRequest(msgIn)
	if !matched {
		httperror.WriteResponse(client, req.URL.RequestURI(), httperror.NoMatch)
		h.logAccess(sess, req.Method, url, "no-match", httperror.NoMatch.Status, treq)
		return false
	}

	oc := newOutcallContext(h.Outcall, ruleSet.UUID(), sess.ClientKey().String(), dst, req.Method, url, req.Header)
	ri := &rules.RequestInterceptor{Req: req}
	if v := applyRequestActions(req.Context(), oc, ri, rule.Request()); v.ShortCircuit {
		if v.Resp != nil {
			httperror.WriteResponse(client, req.URL.RequestURI(), *v.Resp)
			h.logAccess(sess, req.Method, url, requestVerdictOutcome(*v.Resp), v.Resp.Status, treq)
		} else {
			h.logAccess(sess, req.Method, url, "block", 0, treq)
		}
		return false // raise ends with a page; block ends with silence — either way, done
	}

	// A WebSocket/Upgrade request can't go over an h2 upstream connection
	// at all — h2 forbids the Upgrade header outright (RFC 9113 §8.5); real
	// WS-over-h2 needs RFC 8441 extended CONNECT, a different mechanism
	// this proxy doesn't implement. Rather than let it fail against the
	// shared h2 upstream, fall back to a dedicated, h1-only connection to
	// the same origin for just this one request.
	roundTripper := upstream
	if isUpgradeRequest(req) {
		if h2rt, ok := upstream.(*h2RoundTripper); ok {
			fb, ferr := h2rt.H1Fallback(req.Context())
			if ferr != nil {
				spec := classifyConnectErr(ferr)
				httperror.WriteResponse(client, req.URL.RequestURI(), spec)
				h.logAccessErr(sess, req.Method, url, "upgrade-fallback-connect-fail", spec.Status, treq, ferr)
				return false
			}
			defer fb.Close() // closed here unless a 101 below hands ownership to relay()
			roundTripper = fb
		}
	}

	resp, err := roundTripper.RoundTrip(req)
	if err != nil {
		spec := classifyReadErr(err)
		httperror.WriteResponse(client, req.URL.RequestURI(), spec)
		h.logAccessErr(sess, req.Method, url, "upstream-error", spec.Status, treq, err)
		return false
	}
	defer resp.Body.Close()

	// client is always h1 on this path (h2 clients are served by
	// handleH2Stream instead) — but resp may have come from an h2
	// upstream, whose *http.Response carries
	// ProtoMajor=2 and ContentLength=-1 with no TransferEncoding set (h2
	// has no "chunked" wire concept; DATA+END_STREAM frames convey the
	// same "unknown length until it ends" info instead). Writing that
	// unmodified via resp.Write would emit a "HTTP/2.0 200 OK" status line
	// to a real h1 client and, worse, fall back to (*http.Response).Write's
	// HTTP/1.0-style close-terminated framing for the unknown length — a
	// framing signal we then never honor, since closeAfter below is
	// computed from resp.Close (never set by an h2 RoundTrip), so the
	// connection doesn't actually close and the client hangs forever
	// waiting for a length it was never going to get. Normalize to a
	// proper h1 response instead: HTTP/1.1, and chunked framing for a body
	// of unknown length.
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor, resp.ProtoMinor = 1, 1
	if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
		resp.TransferEncoding = []string{"chunked"}
	}

	rri := &rules.ResponseInterceptor{Resp: resp}
	applyResponseActions(rri, rule.Response()) // response actions never short-circuit (no raise/block/webhook in the response registry)

	if rri.StatusOverride != 0 {
		resp.StatusCode = rri.StatusOverride
		resp.Status = fmt.Sprintf("%d %s", rri.StatusOverride, http.StatusText(rri.StatusOverride))
	}
	if rri.BodyOverride != nil {
		resp.Body = io.NopCloser(bytes.NewReader(rri.BodyOverride))
		resp.ContentLength = int64(len(rri.BodyOverride))
		resp.TransferEncoding = nil
	}

	closeAfter := req.Close || resp.Close
	if err := resp.Write(client); err != nil {
		h.logAccessErr(sess, req.Method, url, "client-write-error", resp.StatusCode, treq, err)
		return false
	}
	h.logAccess(sess, req.Method, url, "ok", resp.StatusCode, treq)

	// "WebSocket / CONNECT upgrades: after headers, switch to a raw
	// bidirectional pipe — zero buffering." From here on nothing on this
	// connection is HTTP anymore, so the request/response loop must stop;
	// drain whatever's already buffered on both sides (a fast client/
	// upstream may have started sending frames right behind the 101)
	// before splicing, so no bytes are lost or reordered.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if hj, ok := roundTripper.(rawUpgrader); ok {
			upConn, upBR := hj.Hijack()
			relay(drainBuffered(clientBR, client), drainBuffered(upBR, upConn))
		}
		return false
	}

	return !closeAfter
}

// isUpgradeRequest reports whether req is asking to switch protocols (the
// h1 Connection:Upgrade + Upgrade:<protocol> mechanism — most commonly
// WebSocket). h2 has no wire equivalent (RFC 9113 §8.5 forbids the Upgrade
// header outright), which is exactly why handleOneRequest checks this.
func isUpgradeRequest(req *http.Request) bool {
	if req.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") {
				return true
			}
		}
	}
	return false
}

// isTimeout reports whether err represents a deadline/timeout expiring —
// covers both net.Conn read-deadline errors (h1) and context deadlines
// (h2's per-stream RoundTrip timeout, added alongside the h2 bridge).
func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

// drainBuffered returns a net.Conn that first replays whatever br already
// read into its internal buffer beyond the request it just parsed, then
// falls through to conn — so bytes the client pipelined right behind the
// request (e.g. the ClientHello, immediately after CONNECT) aren't lost.
func drainBuffered(br *bufio.Reader, conn net.Conn) net.Conn {
	n := br.Buffered()
	if n == 0 {
		return conn
	}
	buf, _ := br.Peek(n)
	return Replay(conn, append([]byte(nil), buf...))
}

func writeSimpleResponse(w io.Writer, status int, body string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

func writeCAPEM(w io.Writer, pem []byte) {
	if pem == nil {
		writeSimpleResponse(w, http.StatusNotFound, "Not Found\n")
		return
	}
	fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Type: application/x-pem-file\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(pem))
	w.Write(pem)
}

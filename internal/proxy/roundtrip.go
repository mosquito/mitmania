package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"

	"mitmania/internal/telemetry"
)

// upstream forwarding is expressed as the stdlib http.RoundTripper
// interface throughout handleOneRequest/handleH2Stream — *http2.ClientConn
// already implements it natively (its RoundTrip method matches the
// interface exactly), so h1 and h2 upstream legs are interchangeable to
// the rule-application code without any mitmania-specific interface.

// h1RoundTripper adapts a raw h1 upstream connection to http.RoundTripper.
// Applies readTimeout as a read deadline before ReadResponse, cleared
// before the caller streams the body (mirrors --http-timeout-read's
// "bounds the response start, not the download").
//
// Like h2RoundTripper, it's shared across every keep-alive request forwarded
// over a single client connection's lifetime, and transparently redials when
// the pinned upstream connection turns out to have been closed by the
// origin's own idle timeout in the meantime — otherwise every request after
// that silent close 502s for the rest of the client's session. Unlike h2
// (which can check http2.ClientConn.CanTakeNewRequest before ever writing
// anything), a plain TCP conn gives no such cheap liveness signal — so
// this instead retries once, after the first attempt fails, but only when
// it's provably safe: either nothing reached the wire yet (nothingWritten),
// or the request is idempotent (safe to replay even if the origin did see
// some or all of it before closing the connection).
type h1RoundTripper struct {
	redial      func(ctx context.Context) (net.Conn, error)
	readTimeout time.Duration
	headerLimit int
	log         *slog.Logger // nil disables redial logging
	metrics     *telemetry.Metrics

	// tracer backs the per-request upstream telemetry waterfall: an "upstream"
	// span per RoundTrip call, with "upstream.connect"/"upstream.request"/
	// "upstream.response" children marking the connect-or-reuse, write,
	// and wait-for-headers phases — nil-safe, same convention as metrics.
	tracer trace.Tracer

	mu   sync.Mutex
	conn *prependConn
	br   *bufio.Reader
}

func newH1RoundTripper(conn net.Conn, readTimeout time.Duration, headerLimit int, redial func(ctx context.Context) (net.Conn, error), log *slog.Logger, metrics *telemetry.Metrics, tracer trace.Tracer) *h1RoundTripper {
	stream := newPrependConn(conn)
	return &h1RoundTripper{conn: stream, br: bufio.NewReaderSize(stream, bufioReadSize), readTimeout: readTimeout, headerLimit: headerLimit, redial: redial, log: log, metrics: metrics, tracer: tracer}
}

func (rt *h1RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var upstreamSpan trace.Span
	if rt.tracer != nil {
		ctx, upstreamSpan = rt.tracer.Start(ctx, "upstream", trace.WithAttributes(attribute.String("proto", "h1")))
		defer upstreamSpan.End()
	}

	rt.mu.Lock()
	conn, br := rt.conn, rt.br
	rt.mu.Unlock()

	if span := rt.connectSpan(ctx, true); span != nil {
		span.End()
	}
	resp, err, nothingWritten := rt.roundTripOnce(ctx, conn, br, req)
	if err == nil || rt.redial == nil || errors.Is(err, errHeadersTooLarge) {
		return resp, err
	}
	if !nothingWritten && !isIdempotentMethod(req.Method) {
		return resp, err
	}

	if rt.log != nil {
		rt.log.Debug("h1 upstream connection failed, redialing", "method", req.Method, "err", err.Error())
	}
	connectSpan := rt.connectSpan(ctx, false)
	newConn, dialErr := rt.redial(ctx)
	if connectSpan != nil {
		if dialErr != nil {
			connectSpan.RecordError(dialErr)
		}
		connectSpan.End()
	}
	if dialErr != nil {
		if rt.log != nil {
			rt.log.Debug("h1 redial failed", "err", dialErr.Error())
		}
		return resp, err // report the original failure; the redial attempt is secondary
	}
	newStream := newPrependConn(newConn)
	newBR := bufio.NewReaderSize(newStream, bufioReadSize)
	resp2, err2, _ := rt.roundTripOnce(ctx, newStream, newBR, req)
	if err2 != nil {
		newConn.Close()
		if rt.log != nil {
			rt.log.Debug("h1 redial succeeded but the retried request still failed", "err", err2.Error())
		}
		return resp, err // still report the original failure
	}
	rt.mu.Lock()
	rt.conn, rt.br = newStream, newBR
	rt.mu.Unlock()
	conn.Close() // best-effort: the stale conn's own write/read already failed
	if rt.log != nil {
		rt.log.Debug("h1 redial succeeded")
	}
	return resp2, nil
}

// connectSpan starts the "upstream.connect" child marking this attempt's
// connect phase — reused=true for the zero-cost case where rt's existing
// connection is used as-is (the overwhelmingly common case on a keep-alive
// tunnel), reused=false when a real dial is about to happen (redial).
// Returns nil when rt.tracer is nil — callers must nil-check before End().
func (rt *h1RoundTripper) connectSpan(ctx context.Context, reused bool) trace.Span {
	if rt.tracer == nil {
		return nil
	}
	_, span := rt.tracer.Start(ctx, "upstream.connect", trace.WithAttributes(attribute.Bool("reused", reused)))
	return span
}

// roundTripOnce reports nothingWritten = true only when req.Write never got
// a single byte onto the wire — the case where a retry on a fresh
// connection is unconditionally safe regardless of method.
func (rt *h1RoundTripper) roundTripOnce(ctx context.Context, conn *prependConn, br *bufio.Reader, req *http.Request) (resp *http.Response, err error, nothingWritten bool) {
	var reqSpan trace.Span
	if rt.tracer != nil {
		_, reqSpan = rt.tracer.Start(ctx, "upstream.request")
	}
	cw := &countingWriter{w: conn}
	writeErr := req.Write(cw)
	if reqSpan != nil {
		if writeErr != nil {
			reqSpan.RecordError(writeErr)
		}
		reqSpan.End()
	}
	if writeErr != nil {
		return nil, writeErr, cw.n == 0
	}

	var respSpan trace.Span
	if rt.tracer != nil {
		_, respSpan = rt.tracer.Start(ctx, "upstream.response")
		defer respSpan.End()
	}
	ttfbStart := time.Now()
	if rt.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(rt.readTimeout))
	}
	if err := boundNextHeaderBlock(br, conn, rt.headerLimit); err != nil {
		if rt.readTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}
		if respSpan != nil {
			respSpan.RecordError(err)
		}
		return nil, err, false
	}
	resp, err = http.ReadResponse(br, req)
	if rt.readTimeout > 0 {
		conn.SetReadDeadline(time.Time{})
	}
	if err == nil {
		rt.metrics.UpstreamTTFB(req.Context(), "h1", time.Since(ttfbStart))
		if respSpan != nil {
			respSpan.SetAttributes(attribute.Int("status", resp.StatusCode))
		}
	} else if respSpan != nil {
		respSpan.RecordError(err)
	}
	return resp, err, false
}

// Hijack exposes the current raw connection for a 101 Switching Protocols
// splice — see rawUpgrader.
func (rt *h1RoundTripper) Hijack() (net.Conn, *bufio.Reader) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.conn, rt.br
}

// Close releases whatever upstream connection is current (which may not be
// the one the RoundTripper was constructed with, if a reconnect happened
// since) — relayIntercepted uses rt itself as its upstreamCloser.
func (rt *h1RoundTripper) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.conn == nil {
		return nil
	}
	return rt.conn.Close()
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

func isIdempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// rawUpgrader is implemented by upstream RoundTrippers that can hand back
// their underlying raw connection for a WS/CONNECT-upgrade splice. Only h1
// upstreams implement it: a spec-conformant h2 origin never sends a 101
// response on a stream (RFC 9113 §8.5), so there's nothing to splice there.
type rawUpgrader interface {
	Hijack() (net.Conn, *bufio.Reader)
}

// h2RoundTripper adapts an upstream h2 connection to http.RoundTripper —
// and, unlike a bare *http2.ClientConn, transparently redials when that
// connection goes stale.
//
// Three things it does beyond a bare cc.RoundTrip call:
//
//  1. Request normalization: h2 has no origin-form request-target — the
//     URL must be absolute (scheme+host) and RequestURI must be empty,
//     unlike (*http.Request).Write's tolerant origin-form path used for h1.
//     req may arrive here either straight from http.ReadRequest (origin-
//     form, h1 client) or from http2.Server's own request reconstruction
//     (already has Host, but still carries a server-style RequestURI) —
//     both get the same fix-up, on a clone so the caller's req is untouched.
//
//  2. readTimeout bounds only the wait for response headers, mirroring h1's
//     "cleared before streaming the body". A plain context.WithTimeout
//     can't express that — its timer keeps counting down through body
//     streaming too — so this arms a timer that's explicitly stopped once
//     RoundTrip returns successfully, rather than deferring cancel (which
//     would cancel the context, and h2 ties in-flight Body.Read failures to
//     context cancellation, mid-download).
//
//  3. Reconnect-on-staleness: one h2RoundTripper is shared across every
//     request/stream forwarded over a single client connection's lifetime,
//     which can span many minutes. A real
//     origin can make its side of that connection permanently unusable at
//     any point — GOAWAY, an idle-timeout close, a lost health-check ping —
//     entirely independent of anything the client is doing. Normally
//     http2.Transport's own connection pool dials a fresh connection and
//     retries transparently when that happens; by using
//     Transport.NewClientConn to own exactly one ClientConn ourselves (so
//     the rule engine sees one upstream per client connection, not
//     Transport's pool picking a arbitrary one per request), we lose that
//     for free and have to reimplement it here — otherwise every request
//     after the origin drops the connection 502s for the rest of the
//     client's session, even though a fresh upstream connection would work
//     fine.
type h2RoundTripper struct {
	dialer            UpstreamDialer
	dst, sni          string
	connectTimeout    time.Duration
	connectTries      int
	maxHeaderListSize int
	readTimeout       time.Duration
	log               *slog.Logger // nil disables reconnect logging
	metrics           *telemetry.Metrics

	// tracer backs the per-request upstream telemetry waterfall — see
	// h1RoundTripper.tracer's doc comment; nil-safe the same way.
	tracer trace.Tracer

	mu     sync.Mutex
	cc     *http2.ClientConn
	upConn io.Closer
}

// seed pre-populates rt with an already-open upstream h2 connection — e.g.
// the one TLSService.Terminate dialed to fetch the real cert to clone —
// avoiding a redundant dial before the first request.
func (rt *h2RoundTripper) seed(cc *http2.ClientConn, upConn io.Closer) {
	rt.cc, rt.upConn = cc, upConn
}

// Close releases whatever upstream connection is current at the time it's
// called (which may not be the one seed established, if a reconnect
// happened since) — relayIntercepted/serveH2 use rt itself as their
// upstreamCloser rather than tracking the raw conn separately.
func (rt *h2RoundTripper) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.upConn == nil {
		return nil
	}
	return rt.upConn.Close()
}

// H1Fallback dials a dedicated, h1-only connection to the same origin rt
// was built for — for a single request (a WebSocket Upgrade) that needs
// real h1 wire semantics h2 structurally can't provide. It's a one-off:
// not shared with rt's own pooled ClientConn, not cached, and the caller
// owns closing it (via the returned *h1RoundTripper's Close, or by taking
// over its Hijacked conn for a splice).
func (rt *h2RoundTripper) H1Fallback(ctx context.Context) (*h1RoundTripper, error) {
	conn, err := rt.dialer.DialTLSH1Only(ctx, "tcp", rt.dst, rt.sni)
	if err != nil {
		return nil, err
	}
	return newH1RoundTripper(conn, rt.readTimeout, rt.maxHeaderListSize, nil, rt.log, rt.metrics, rt.tracer), nil
}

// currentConn returns rt's live upstream ClientConn, redialing first if the
// existing one (if any) can no longer take new requests. reused reports
// whether cc was already open and just handed back as-is (true) versus a
// fresh dial/reconnect just happened (false) — surfaced on the
// "upstream.connect" span the same way h1RoundTripper's does.
func (rt *h2RoundTripper) currentConn(ctx context.Context) (cc *http2.ClientConn, reused bool, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.cc != nil && rt.cc.CanTakeNewRequest() {
		return rt.cc, true, nil
	}
	// The old connection can't take NEW requests, but other streams on it
	// (from concurrent client streams sharing this same h2RoundTripper —
	// e.g. a page loading many resources at once) may well still be
	// in-flight. Closing rt.upConn here immediately would sever those too
	// ("use of closed network connection"), when h2's own semantics
	// (GOAWAY) already let in-flight streams finish on their own — so
	// hand it off to drain in the background instead of closing it inline.
	if rt.cc != nil {
		if rt.log != nil {
			rt.log.Debug("h2 upstream connection stale, reconnecting", "dst", rt.dst, "sni", rt.sni)
		}
		staleCC, staleConn := rt.cc, rt.upConn
		go func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			staleCC.Shutdown(shutdownCtx)
			staleConn.Close()
		}()
	}
	newCC, upConn, dialErr := newUpstreamH2ClientConn(ctx, rt.dialer, rt.log, rt.dst, rt.sni, rt.connectTries, rt.connectTimeout, rt.maxHeaderListSize, nil)
	if dialErr != nil {
		rt.cc, rt.upConn = nil, nil
		if rt.log != nil {
			rt.log.Debug("h2 reconnect failed", "dst", rt.dst, "sni", rt.sni, "err", dialErr.Error())
		}
		return nil, false, dialErr
	}
	rt.cc, rt.upConn = newCC, upConn
	return newCC, false, nil
}

func (rt *h2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	var upstreamSpan trace.Span
	if rt.tracer != nil {
		ctx, upstreamSpan = rt.tracer.Start(ctx, "upstream", trace.WithAttributes(attribute.String("proto", "h2")))
		defer upstreamSpan.End()
	}

	var connectSpan trace.Span
	if rt.tracer != nil {
		_, connectSpan = rt.tracer.Start(ctx, "upstream.connect")
	}
	cc, reused, err := rt.currentConn(ctx)
	if connectSpan != nil {
		connectSpan.SetAttributes(attribute.Bool("reused", reused))
		if err != nil {
			connectSpan.RecordError(err)
		}
		connectSpan.End()
	}
	if err != nil {
		return nil, err
	}

	var cancel context.CancelFunc
	var timer *time.Timer
	if rt.readTimeout > 0 {
		ctx, cancel = context.WithCancel(ctx)
		timer = time.AfterFunc(rt.readTimeout, cancel)
	}

	out := req.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = "https"
	if out.URL.Host == "" {
		out.URL.Host = out.Host
	}

	// http2.ClientConn.RoundTrip sends the request and waits for response
	// headers as one atomic call — unlike h1, there's no observable
	// boundary between "request fully written" and "waiting for the
	// response" to split into separate upstream.request/upstream.response
	// spans, so this is a single "upstream.response" span covering both
	// (its duration is exactly what UpstreamTTFB already records).
	var respSpan trace.Span
	if rt.tracer != nil {
		_, respSpan = rt.tracer.Start(ctx, "upstream.response")
	}
	ttfbStart := time.Now()
	resp, err := cc.RoundTrip(out)
	if err == nil {
		rt.metrics.UpstreamTTFB(req.Context(), "h2", time.Since(ttfbStart))
		if respSpan != nil {
			respSpan.SetAttributes(attribute.Int("status", resp.StatusCode))
		}
	} else if respSpan != nil {
		respSpan.RecordError(err)
	}
	if respSpan != nil {
		respSpan.End()
	}

	if timer != nil {
		if !timer.Stop() {
			// The timer already fired (and canceled ctx) racing RoundTrip's
			// return — treat it as a timeout uniformly, even if a response
			// technically arrived right as that happened.
			if err == nil {
				resp.Body.Close()
			}
			return nil, context.DeadlineExceeded
		}
		if err != nil {
			cancel()
		}
	}
	return resp, err
}

// newUpstreamH2ClientConn wraps first — when non-nil, an already-open
// upstream TLS connection (e.g. the one TLSService.Terminate dialed to
// fetch the real cert to clone) — in an *http2.ClientConn, retrying the
// preface/SETTINGS exchange up to connectTries times (each attempt bounded
// by connectTimeout). first is only reused on the very first attempt; a
// retry (or a reconnect from h2RoundTripper.currentConn, which always
// passes nil) dials a brand-new upstream TLS connection — the cert clone
// already happened against first's peer certificates the first time this
// connection was established, so no re-clone is needed, just a fresh dial.
// maxHeaderListSize bounds upstream response headers (--http-header-limit,
// mirroring the client-facing http2.Server's own BaseConfig.MaxHeaderBytes)
// — a fresh *http2.Transport is built per call rather than sharing one
// package-level instance so this can vary without a data race on a shared
// field.
func newUpstreamH2ClientConn(ctx context.Context, dialer UpstreamDialer, log *slog.Logger, dst, sni string, connectTries int, connectTimeout time.Duration, maxHeaderListSize int, first *tls.Conn) (*http2.ClientConn, *tls.Conn, error) {
	t := &http2.Transport{MaxHeaderListSize: uint32(maxHeaderListSize)}
	conn := first
	cc, err := withRetries(ctx, log, "h2_connect "+dst, connectTries, connectTimeout, func(attemptCtx context.Context) (*http2.ClientConn, error) {
		if conn == nil {
			dialed, dialErr := dialer.DialTLS(attemptCtx, "tcp", dst, sni)
			if dialErr != nil {
				return nil, dialErr
			}
			conn = dialed
		}
		cc, err := t.NewClientConn(conn)
		if err != nil {
			conn.Close()
			conn = nil
			return nil, err
		}
		return cc, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return cc, conn, nil
}

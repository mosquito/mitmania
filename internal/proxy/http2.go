package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/net/http2"

	"mitmania/internal/httperror"
	"mitmania/internal/rules"
	"mitmania/internal/session"
)

// http2Server is stateless beyond per-connection ServeConn setup — safe to
// share across every client h2 connection this process serves.
var http2Server = &http2.Server{}

// serveH2 runs the client-facing HTTP/2 leg of an intercepted connection:
// http2.Server.ServeConn multiplexes concurrent streams on
// client, each one applying the same rule-engine pipeline as the h1 path
// via a single shared upstream h2 connection (http2.ClientConn.RoundTrip is
// safe to call concurrently). Reached only when TLSService.Terminate
// negotiated h2 with the client, which by construction only ever happens
// when upstream also negotiated h2.
func (h *Http1Handler) serveH2(ctx context.Context, sess session.Session, dialer UpstreamDialer, client *tls.Conn, upstreamFirst *tls.Conn, dst, sni string, connIn rules.ConnInput, principal string) {
	ctx, treq := h.startReq(ctx, "h2", http.MethodConnect, connIn.Proto+"://"+sni)
	defer client.Close()

	cc, upConn, err := newUpstreamH2ClientConn(ctx, dialer, h.Logger, dst, sni, h.HTTP2ConnectTries, h.HTTP2ConnectTimeout, h.HeaderLimit, upstreamFirst)
	if err != nil {
		h.logAccessErr(sess, http.MethodConnect, connIn.Proto+"://"+sni, "h2-connect-fail", 0, treq, err)
		return
	}
	roundTripper := &h2RoundTripper{dialer: dialer, dst: dst, sni: sni, connectTimeout: h.HTTP2ConnectTimeout, connectTries: h.HTTP2ConnectTries, maxHeaderListSize: h.HeaderLimit, readTimeout: h.HTTP2ReadTimeout, log: h.Logger, metrics: h.Metrics, tracer: h.Tracer}
	roundTripper.seed(cc, upConn)
	defer roundTripper.Close()
	if treq.span != nil {
		treq.span.End() // upstream h2 setup succeeded; each stream gets its own span from handleH2Stream
	}

	http2Server.ServeConn(client, &http2.ServeConnOpts{
		Context:    ctx,
		BaseConfig: &http.Server{MaxHeaderBytes: h.HeaderLimit},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.handleH2Stream(ctx, sess, w, r, roundTripper, connIn, dst, principal)
		}),
	})
}

// handleH2Stream is http2Bridge's per-stream twin of handleOneRequest: same
// rule lookup / request actions / forward / response actions pipeline,
// expressed against http.ResponseWriter instead of a raw client net.Conn
// since http2.Server hands us a callback rather than a connection to read
// from directly.
func (h *Http1Handler) handleH2Stream(ctx context.Context, sess session.Session, w http.ResponseWriter, r *http.Request, upstream http.RoundTripper, connIn rules.ConnInput, dst string, principal string) {
	if h.Flow != nil {
		h.Flow.RequestServed()
	}
	url := requestURL(connIn, r)
	ctx, treq := h.startReq(ctx, "h2", r.Method, url)
	treq.withDst(dst) // already pinned/resolved by serveConnect before serveH2 handed off
	if principal != "" {
		treq.withPrincipal(principal)
	}
	r = r.WithContext(ctx)

	// Coalescing defense: reject any stream whose :authority isn't the
	// single host this connection was actually dialed for — a browser
	// reusing this h2 connection for a different origin (spec-legal when
	// SAN coverage + DNS overlap allow it) must open a fresh connection
	// instead, rather than being served over a cert never verified against
	// upstream for that other host (cert cloning keeps the full SAN set
	// faithful to the real chain; this per-stream guard is the defense,
	// not weaker certs).
	if !authorityMatches(r.Host, connIn.Host, connIn.Port, connIn.Proto) {
		httperror.Handle(w, r.URL.RequestURI(), httperror.MisdirectedRequest)
		h.logAccess(sess, r.Method, url, "misdirected-authority", httperror.MisdirectedRequest.Status, treq)
		return
	}

	ruleSet, err := h.Rules.Lookup(r.Context(), sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, r.Method, url, "rule-engine-error", 0, treq, err)
		panic(http.ErrAbortHandler) // silent stream reset, matching h1's "return false" with no page
	}

	msgIn := rules.MsgInput{ConnInput: connIn, Path: r.URL.Path, Method: r.Method, Header: r.Header}
	rule, matched := ruleSet.LookupRequest(msgIn)
	if !matched {
		httperror.Handle(w, r.URL.RequestURI(), httperror.NoMatch)
		h.logAccess(sess, r.Method, url, "no-match", httperror.NoMatch.Status, treq)
		return
	}

	oc := newOutcallContext(h.Outcall, ruleSet.UUID(), sess.ClientKey().String(), dst, r.Method, url, r.Header)
	ri := &rules.RequestInterceptor{Req: r}
	if v := applyRequestActions(r.Context(), oc, ri, rule.Request()); v.ShortCircuit {
		if v.Resp != nil {
			httperror.Handle(w, r.URL.RequestURI(), *v.Resp)
			h.logAccess(sess, r.Method, url, requestVerdictOutcome(*v.Resp), v.Resp.Status, treq)
		} else {
			h.logAccess(sess, r.Method, url, "block", 0, treq)
			panic(http.ErrAbortHandler)
		}
		return
	}

	var reqBody *countingReadCloser
	if r.Body != nil {
		reqBody = &countingReadCloser{ReadCloser: r.Body}
		r.Body = reqBody
	}
	resp, err := upstream.RoundTrip(r)
	if reqBody != nil {
		h.Metrics.BytesStreamed(ctx, "up", reqBody.n) // whatever the transport actually read, even on error below
	}
	if err != nil {
		spec := classifyReadErr(err)
		httperror.Handle(w, r.URL.RequestURI(), spec)
		h.logAccessErr(sess, r.Method, url, "upstream-error", spec.Status, treq, err)
		return
	}
	defer resp.Body.Close()

	rri := &rules.ResponseInterceptor{Resp: resp}
	applyResponseActions(rri, rule.Response()) // response actions never short-circuit (no raise/block/webhook in the response registry)

	status := resp.StatusCode
	if rri.StatusOverride != 0 {
		status = rri.StatusOverride
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if rri.BodyOverride != nil {
		w.Header().Set("Content-Length", strconv.Itoa(len(rri.BodyOverride)))
		w.WriteHeader(status)
		n, _ := w.Write(rri.BodyOverride)
		h.Metrics.BytesStreamed(ctx, "down", int64(n))
	} else {
		w.WriteHeader(status)
		n := func() int64 {
			buf := getCopyBuf()
			defer putCopyBuf(buf)
			n, _ := io.CopyBuffer(w, resp.Body, *buf)
			return n
		}()
		h.Metrics.BytesStreamed(ctx, "down", n)
	}

	h.logAccess(sess, r.Method, url, "ok", status, treq)
}

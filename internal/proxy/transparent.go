package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"

	"mitmania/internal/rules"
	"mitmania/internal/session"
)

// serveTransparent is the entry point for a TPROXY/REDIRECT-accepted
// session (sess.Transport != TransportExplicit): there is no CONNECT or
// absolute-form request carrying the destination authority, and no
// response channel to describe a failure on the way a CONNECT tunnel's
// "200"/non-200 or an absolute-form request's status line has — sess.Dst
// is already the true destination (recovered by the Acceptor at accept
// time), and "host" for connection-phase rule matching has to come from
// peeking the traffic itself before any matching happens, the reverse of
// serveConnect's peek-after-match order (see serveTunnel's doc comment).
// Every failure path here drops the connection rather than writing a
// response, since a transparently-intercepted client has no reason to
// expect one.
func (h *Http1Handler) serveTransparent(ctx context.Context, sess session.Session, dialer UpstreamDialer) {
	dstAddr := sess.Dst.Addr().String()
	dstPort := strconv.Itoa(int(sess.Dst.Port()))

	hello, err := PeekClientHello(sess.Conn)
	if err == nil {
		h.serveTransparentTLS(ctx, sess, dialer, hello, dstAddr, dstPort)
		return
	}
	// Not a TLS ClientHello (or a malformed/truncated one) — hello.Raw
	// still holds whatever bytes were read while peeking (PeekClientHello
	// returns it alongside the error precisely so a caller can fall
	// through without losing them), so nothing is lost moving to the
	// plaintext path.
	h.serveTransparentHTTP(ctx, sess, dialer, hello.Raw, dstAddr, dstPort)
}

// serveTransparentTLS handles a transparently-intercepted TLS connection:
// SNI (when present — a client is not required to send one) is the only
// available domain signal, so it both supplies connIn.Host for matching
// and, unlike serveConnect, needs no separate consistency check against
// anything else. Absent SNI, the literal destination IP is used as Host
// instead — resolveAndPin already treats a literal-IP host as a no-DNS
// pin (see egress.go), so this reuses that path rather than inventing a
// second fallback concept.
func (h *Http1Handler) serveTransparentTLS(ctx context.Context, sess session.Session, dialer UpstreamDialer, hello *PeekedHello, dstAddr, dstPort string) {
	method := sess.Transport.String()

	// The SNI, not the kernel-recovered destination IP, is what a rule
	// actually matched against — logging/tracing on the IP alone would
	// make an access-log line for a domain-based rule unreadable (every
	// host behind the same load balancer or CDN edge logs identically).
	// Falls back to the IP only when the client sent no SNI at all, same
	// as connIn.Host below.
	sni := hello.ServerName
	if sni == "" {
		sni = dstAddr
	}
	reqURL := "https://" + net.JoinHostPort(sni, dstPort)
	ctx, treq := h.startReq(ctx, "h1", method, reqURL)

	connIn := rules.ConnInput{Host: sni, Port: dstPort, Proto: "https"}

	ruleSet, err := h.Rules.Lookup(ctx, sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, method, reqURL, "rule-engine-error", 0, treq, err)
		return
	}

	// auth.http_proxy's own transport check already fails this closed
	// (see checkAuth) — a transparent client has no Proxy-Authorization
	// channel, so a required gate reached this way is always denied. The
	// synthetic request only needs Method (used for the denial's access
	// log line); checkAuth never reads Header on this path.
	principal, authOK := h.checkAuth(ctx, sess, ruleSet, &http.Request{Method: method}, reqURL, treq)
	if !authOK {
		return
	}
	if principal != "" {
		treq.withPrincipal(principal)
	}

	mitm, matched := ruleSet.LookupConn(connIn)
	if !matched {
		h.logAccess(sess, method, reqURL, "no-match", 0, treq)
		return
	}

	// Egress-policy resolve-phase, same as serveConnect — except the
	// "host" being resolved is already a literal IP (the kernel-recovered
	// Dst), so resolveAndPin's DNS-resolve step is always skipped here;
	// only the egress check and pin remain.
	pinned, err := resolveAndPin(ctx, ruleSet, dialer, dstAddr, dstPort, "http")
	if err != nil {
		outcome := "resolve-fail"
		var denied *egressDeniedError
		if errors.As(err, &denied) {
			outcome = "forwarding-denied"
		}
		h.logAccessErr(sess, method, reqURL, outcome, 0, treq, err)
		return
	}
	dst := pinned
	treq.withDst(dst)

	// No reachability probe before proceeding, unlike serveConnect — that
	// probe exists purely to report a connect failure on the CONNECT
	// response before committing to "200 Connection Established"; there
	// is no such response here to report anything on, so the real dial
	// inside serveTunnel (splice or TLS terminate) is the only dial
	// attempt.
	replayed := Replay(sess.Conn, hello.Raw)
	h.serveTunnel(ctx, sess, replayed, dialer, dst, sni, connIn, mitm, method, reqURL, treq, principal)
}

// serveTransparentHTTP handles a transparently-intercepted plaintext HTTP
// connection: peeked is whatever bytes PeekClientHello already consumed
// determining this isn't TLS, replayed back before parsing so nothing is
// lost. Plain HTTP has no encryption to strip, so — mirroring
// serveAbsoluteForm exactly — the connection-phase rule's mitm bool is
// never consulted here: message-phase policy always runs through the
// ordinary h1 relay, the same as it does for an explicit absolute-form
// request.
func (h *Http1Handler) serveTransparentHTTP(ctx context.Context, sess session.Session, dialer UpstreamDialer, peeked []byte, dstAddr, dstPort string) {
	ctx, treq := h.startReq(ctx, "h1", "", "")
	method := sess.Transport.String()

	stream := newPrependConn(sess.Conn)
	stream.prepend(peeked)
	sess.Conn = stream // relayIntercepted's client and firstBR must share one reader chain, same as Serve()'s dispatch wrapping
	br := bufio.NewReaderSize(stream, bufioReadSize)

	if err := boundNextHeaderBlock(br, stream, h.HeaderLimit); err != nil {
		// Very common and entirely benign on a transparent listener:
		// connection racing (a client, e.g. an iOS device doing Happy
		// Eyeballs, opens several TCP connections and aborts every loser
		// without writing to it) and plain TCP-level health checks both
		// land here as a connection that closed before sending anything —
		// distinct from a client that sent bytes that didn't parse.
		outcome := "invalid-request"
		switch {
		case errors.Is(err, errEmptyConnection):
			outcome = "empty-connection"
		case errors.Is(err, errHeadersTooLarge):
			outcome = "headers-too-large"
		}
		h.logAccessErr(sess, method, "", outcome, 0, treq, err)
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		h.logAccessErr(sess, method, "", "invalid-request", 0, treq, err)
		return
	}

	host := req.Host
	if host == "" {
		host = dstAddr
	}
	// req.Host may carry its own port (rare for a browser-issued Host
	// header, but valid); only the host half matters for matching — the
	// destination port used for dialing/pinning is always the
	// transparently recovered one, never anything the client claims.
	hostOnly, _, _, err := normalizeAuthority(host, dstPort)
	if err != nil {
		h.logAccessErr(sess, method, req.URL.String(), "invalid-host-header", 0, treq, err)
		return
	}
	connIn := rules.ConnInput{Host: hostOnly, Port: dstPort, Proto: "http"}
	reqURL := "http://" + hostOnly + req.URL.RequestURI()

	ruleSet, err := h.Rules.Lookup(ctx, sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, req.Method, reqURL, "rule-engine-error", 0, treq, err)
		return
	}

	principal, authOK := h.checkAuth(ctx, sess, ruleSet, req, reqURL, treq)
	if !authOK {
		return
	}
	if principal != "" {
		treq.withPrincipal(principal)
	}
	req.Header.Del("Proxy-Authorization") // hop-by-hop, never forwarded upstream — same as serveAbsoluteForm

	if _, matched := ruleSet.LookupConn(connIn); !matched {
		h.logAccess(sess, req.Method, reqURL, "no-match", 0, treq)
		return
	}

	pinned, err := resolveAndPin(ctx, ruleSet, dialer, dstAddr, dstPort, "http")
	if err != nil {
		outcome := "resolve-fail"
		var denied *egressDeniedError
		if errors.As(err, &denied) {
			outcome = "forwarding-denied"
		}
		h.logAccessErr(sess, req.Method, reqURL, outcome, 0, treq, err)
		return
	}
	dst := pinned
	treq.withDst(dst)

	upstream, err := dialer.Dial(ctx, "tcp", dst)
	if err != nil {
		h.logAccessErr(sess, req.Method, reqURL, "connect-fail", 0, treq, err)
		return
	}

	// req.Host already carries the origin host; req.URL is already
	// origin-form (a transparently-intercepted client never sends
	// absolute-form), so nothing needs clearing here the way
	// serveAbsoluteForm clears URL.Scheme/Host before forwarding.
	redial := func(redialCtx context.Context) (net.Conn, error) {
		return dialer.Dial(redialCtx, "tcp", dst)
	}
	roundTripper := newH1RoundTripper(upstream, h.ReadTimeout, h.HeaderLimit, redial, h.Logger, h.Metrics, h.Tracer)
	if treq.span != nil {
		treq.span.End() // request is handed off; relayIntercepted starts its own per-request spans from here
	}
	h.relayIntercepted(ctx, sess, sess.Conn, roundTripper, roundTripper, connIn, dst, req, br, principal)
}

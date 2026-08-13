package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

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
//
// Only one signal is ever used to identify a connection: the TLS SNI, if
// PeekClientHello recognizes one — nothing else is guessed at. A
// transparent listener sees whatever traffic an operator's REDIRECT/
// TPROXY capture rule sends it, not just HTTP(S): some of it is
// genuinely uninspectable (Telegram's MTProto "obfuscated" transport
// deliberately looks like neither TLS nor anything else, precisely to
// defeat this kind of protocol classification), and it never closes its
// connection just to help a guessing game along — it sends its initial
// bytes and waits for a response. Trying to sniff "is this maybe HTTP"
// from content would mean either guessing wrong or waiting indefinitely
// for confirmation that will never come. Anything that isn't a
// recognized TLS ClientHello is handled identically regardless of what
// it actually is: matched on the literal destination IP via
// serveTransparentOpaque, mitm:false only (there is nothing to
// terminate/decrypt for content mitmania never identified).
func (h *Http1Handler) serveTransparent(ctx context.Context, sess session.Session, dialer UpstreamDialer) {
	dstAddr := sess.Dst.Addr().String()
	dstPort := strconv.Itoa(int(sess.Dst.Port()))
	method := sess.Transport.String()

	// Bounds the wait for the client's first complete ClientHello (see
	// Http1Handler.ClientReadTimeout) — cleared once a decision is made,
	// same convention as Serve's explicit-mode path.
	if h.ClientReadTimeout > 0 {
		sess.Conn.SetReadDeadline(time.Now().Add(h.ClientReadTimeout))
	}

	hello, err := PeekClientHello(sess.Conn)
	if err == nil {
		h.serveTransparentTLS(ctx, sess, dialer, hello, dstAddr, dstPort)
		return
	}

	if h.ClientReadTimeout > 0 {
		sess.Conn.SetReadDeadline(time.Time{})
	}

	if len(hello.Raw) == 0 {
		// Nothing was ever sent — a speculative/aborted TCP connection
		// (connection racing, a health check) or the deadline above
		// firing on a client that never sent anything at all. Neither is
		// traffic to make an opaque-TCP decision about: there's no
		// content to match on some destination even if we wanted to,
		// since the decision is IP-based, not content-based, but a
		// connection carrying zero bytes isn't really "traffic" at all.
		_, treq := h.startReq(ctx, "h1", method, "")
		outcome, logErr := "empty-connection", fmt.Errorf("%w: %w", errEmptyConnection, err)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			outcome, logErr = "client-read-timeout", err
		}
		h.logAccessErr(sess, method, "", outcome, 0, treq, logErr)
		return
	}

	// Not TLS, but the client did send something — peeking further to
	// decide "is this maybe HTTP" would be exactly the guessing game
	// this function's doc comment rules out. Everything peeked so far is
	// still on the wire, ready to replay: PeekClientHello's own
	// recordingConn records every byte it actually read.
	ctx, treq := h.startReq(ctx, "h1", method, "")
	stream := newPrependConn(sess.Conn)
	stream.prepend(hello.Raw)
	sess.Conn = stream
	h.serveTransparentOpaque(ctx, sess, dialer, stream, dstAddr, dstPort, method, treq)
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
	if h.ClientReadTimeout > 0 {
		sess.Conn.SetReadDeadline(time.Time{})
	}
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

// serveTransparentOpaque is the fallback for any transparently-
// intercepted connection that PeekClientHello didn't recognize as TLS —
// some apps deliberately obfuscate their traffic to look like neither TLS
// nor anything else (Telegram's MTProto "obfuscated" transport on 443 is
// exactly this: random-looking bytes, no SNI, by design, specifically to
// defeat this kind of protocol classification), and others are simply
// plain, unencrypted HTTP. connIn.Host is the literal destination IP —
// there is no fallback domain signal at all here, not even TLS's
// SNI-absent case, since nothing about this traffic is identified yet.
// Proto is the fixed sentinel "tcp", so an operator must name it
// explicitly in a rule; ordinary TLS traffic always matches via
// serveTransparentTLS's "https" and never reaches this function.
//
// The connection-phase decision itself (mitm true/false) is made purely
// from that IP match — never from guessing at content, which would make
// the single most security-relevant decision in the whole pipeline
// depend on an unreliable heuristic. What happens next depends on what
// was decided:
//
//   - mitm:false — splice raw, byte-perfect, no further inspection.
//     mitmania cannot decrypt or parse what it hasn't identified, so this
//     is the only thing a plain "allow this destination" rule can mean.
//   - mitm:true — the operator has explicitly asked for interception at
//     this destination, so it's no longer a guess to go try parsing it:
//     HTTP is the only protocol mitmania knows how to intercept, so
//     serveTransparentOpaqueMITM attempts exactly that, using the
//     request's own Host header (once parsed) for message-phase policy —
//     the ordinary HTTP interception path, just reached via IP-based
//     gating instead of TLS/SNI. If it isn't HTTP either, there is
//     nothing to intercept and the connection fails closed rather than
//     silently downgrading to a splice the operator didn't ask for.
func (h *Http1Handler) serveTransparentOpaque(ctx context.Context, sess session.Session, dialer UpstreamDialer, stream *prependConn, dstAddr, dstPort, method string, treq reqTrace) {
	reqURL := "tcp://" + net.JoinHostPort(dstAddr, dstPort)
	connIn := rules.ConnInput{Host: dstAddr, Port: dstPort, Proto: "tcp"}

	ruleSet, err := h.Rules.Lookup(ctx, sess.ClientKey())
	if err != nil {
		h.logAccessErr(sess, method, reqURL, "rule-engine-error", 0, treq, err)
		return
	}

	// Same transport-check-always-fails-closed reasoning as
	// serveTransparentTLS: a transparent client has no Proxy-Authorization
	// channel, so a required auth.http_proxy gate is always denied here.
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

	if mitm {
		h.serveTransparentOpaqueMITM(ctx, sess, dialer, stream, dstAddr, dstPort, method, treq)
		return
	}

	pinned, err := resolveAndPin(ctx, ruleSet, dialer, dstAddr, dstPort, "tcp")
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

	h.serveTunnel(ctx, sess, stream, dialer, dst, "", connIn, false, method, reqURL, treq, principal)
}

// serveTransparentOpaqueMITM attempts to parse and intercept a
// connection whose connection-phase decision (via serveTransparentOpaque,
// matched on the literal destination IP since this traffic isn't TLS) was
// mitm:true — mirroring serveAbsoluteForm/the old plain-HTTP path
// exactly: no encryption to strip, so the connection-phase rule's mitm
// bool has already done its job by getting here; message-phase policy
// runs through the ordinary h1 relay, re-matched on the parsed request's
// own Host header (which may name a different, more specific rule than
// the IP-based one that granted mitm:true in the first place — same
// two-stage relationship serveConnect's CONNECT-then-message-phase
// matching already has). If this genuinely isn't HTTP either, there is
// nothing to intercept: fails closed rather than silently downgrading to
// a raw splice the operator didn't ask for.
func (h *Http1Handler) serveTransparentOpaqueMITM(ctx context.Context, sess session.Session, dialer UpstreamDialer, stream *prependConn, dstAddr, dstPort, method string, treq reqTrace) {
	br := bufio.NewReaderSize(stream, bufioReadSize)

	if err := boundNextHeaderBlock(br, stream, h.HeaderLimit); err != nil {
		outcome := "invalid-request"
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			outcome = "client-read-timeout"
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
	if h.ClientReadTimeout > 0 {
		stream.SetReadDeadline(time.Time{})
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

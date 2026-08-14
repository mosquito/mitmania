package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"mitmania/internal/session"
)

// runTransparentProxy starts a Dispatcher/Http1Handler behind a real TCP
// listener, tagging every accepted session as transparent with the given
// transport/dst — standing in for a real RedirectAcceptor/TProxyAcceptor,
// which need actual kernel-level NAT/policy routing to populate Dst
// meaningfully (see internal/session's Linux-gated tests, and the
// project's live nftables smoke test, for that half). A test client
// dials the returned address directly: no CONNECT, no proxy
// configuration, exactly how a transparently-intercepted client behaves.
func runTransparentProxy(t *testing.T, handler *Http1Handler, transport session.Transport, dst netip.AddrPort) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	disp := &Dispatcher{Selector: &Selector{Default: handler}, Dialer: NewUpstreamDialer(5*time.Second, 1)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var client netip.AddrPort
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				client = tcpAddr.AddrPort()
			}
			sess := session.Session{Client: client, Dst: dst, Transport: transport, Conn: conn, Acceptor: "test-transparent"}
			go disp.Handle(context.Background(), sess)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", s, err)
	}
	return ap
}

// TestServeTransparent_TLS_SNIMatch_Splice proves the core claim: a
// TPROXY/REDIRECT session with no CONNECT authority at all still gets
// domain-based mitm:false policy, by peeking the ClientHello's SNI
// before any rule match — exactly like the explicit CONNECT path's
// mitm:false splice, just reached without ever seeing a CONNECT.
func TestServeTransparent_TLS_SNIMatch_Splice(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "raw origin response")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	dst := mustAddrPort(t, target)

	ruleJSON := `{"http":[{"match":{"host":"sni.example"},"mitm":false}]}`
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "sni.example", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	gotLeaf := tlsConn.ConnectionState().PeerCertificates[0]
	if !gotLeaf.Equal(origin.Certificate()) {
		t.Fatalf("client saw a different cert than the origin's real one — mitm:false did not splice raw")
	}

	req, _ := http.NewRequest(http.MethodGet, "https://sni.example/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "raw origin response" {
		t.Fatalf("body = %q, want raw origin response", body)
	}
}

// TestServeTransparent_TLS_SNIMatch_MITMTerminate proves the mitm:true
// side of the same decision: message-phase policy (a response mutation
// here) applies to a transparently-intercepted TLS connection exactly as
// it would to an explicit CONNECT.
func TestServeTransparent_TLS_SNIMatch_MITMTerminate(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "original")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	// SNI must be a name the origin's real cert actually covers: mitm:true
	// clones the origin's cert verbatim (subject/SAN preserved, per
	// CLAUDE.md's cert-cloning invariant), not one naming whatever SNI the
	// client happened to request — httptest.NewTLSServer's default cert
	// covers example.com/*.example.com.
	ruleJSON := `{"http":[{"match":{"host":"example.com"},
	  "response":[{"action":"body.replace","params":{"body":"mutated"}}]}]}`
	handler, caPEM := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportTProxy, dst)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, &tls.Config{ServerName: "example.com", RootCAs: pool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// As with the plaintext-HTTP test: the request's implied port (443,
	// absent one in the URL) must match connIn.Port (the real,
	// kernel-recovered Dst port — an ephemeral test port here, not 443)
	// for relayIntercepted's per-request authorityMatches check to pass.
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://example.com:%d/", dst.Port()), nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "mutated" {
		t.Fatalf("body = %q, want mutated (message-phase policy did not apply)", body)
	}
}

// TestServeTransparent_HTTP_HostHeaderMatch proves the plaintext-HTTP
// half: a transparently-intercepted origin-form request (no CONNECT, no
// absolute-form — exactly what a real TPROXY/REDIRECT-caught HTTP client
// sends) is matched on its Host header and relayed through the ordinary
// message-phase engine, mirroring serveAbsoluteForm's behavior for an
// explicit client. Getting there needs two rule entries now: the
// connection-phase decision is always made on the literal destination IP
// (never guessed from content — see serveTransparent's doc comment), so
// an IP-scoped proto:"tcp" entry is what grants mitm:true and lets the
// HTTP parse happen at all; only once that's granted does the Host-header
// rule take over for message-phase policy, the same two-stage
// relationship CONNECT-then-message-phase matching already has.
func TestServeTransparent_HTTP_HostHeaderMatch(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host seen: %s", r.Host)
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	ruleJSON := fmt.Sprintf(`{"http":[
	  {"match":{"host":%q,"proto":"tcp"}},
	  {"match":{"host":"host.example"}}
	]}`, dst.Addr().String())
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	// The Host header carries the port the client believes it's talking
	// to — relayIntercepted's per-request authorityMatches check compares
	// it against connIn.Port (the real, kernel-recovered Dst port), so it
	// must be explicit here since the origin's real port is an ephemeral
	// test port, not the default-80 a bare "host.example" would imply.
	hostHeader := fmt.Sprintf("host.example:%d", dst.Port())
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	want := "host seen: " + hostHeader
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestServeTransparent_NoMatch_FailsClosed is the connection-phase
// negative test: a transparent client whose SNI matches nothing gets the
// connection dropped, not an HTTP-shaped error response — there is no
// response channel a transparently-intercepted client would understand
// (see serveTransparent's doc comment). Proving "the connection closes
// with no bytes" rather than assuming it is the actual security-relevant
// claim here: a leftover response-writing code path would leak
// proxy-shaped bytes to a client that never asked to talk to a proxy.
func TestServeTransparent_NoMatch_FailsClosed(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should never be dialed for a connection-phase no-match")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	handler, _ := newTestHandler(t, `{"http":[{"match":{"host":"only-this.example"}}]}`)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "unmatched.example", InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	err = tlsConn.Handshake()
	if err == nil {
		t.Fatal("Handshake: want an error (connection dropped after no-match), got success")
	}
}

// TestServeTransparent_TLS_ConnectionDeny_ConnectionDropped proves
// serveTransparentTLS's deny branch: a connection: {"accept": false} match
// on SNI drops the connection with no bytes written at all — same as a
// no-match, but reached via a rule that explicitly named this host rather
// than an absence of any matching rule.
func TestServeTransparent_TLS_ConnectionDeny_ConnectionDropped(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should never be dialed for a denied connection")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	handler, _ := newTestHandler(t, `{"http":[{"match":{"host":"ads.example"},"connection":{"accept":false}}]}`)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "ads.example", InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("Handshake: want an error (connection dropped after deny), got success")
	}

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=denied") {
		t.Fatalf("outcome = %q, want denied", log)
	}
}

// TestServeTransparent_OpaqueTCP_ConnectionDeny_ConnectionDropped proves
// serveTransparentOpaque's deny branch: a connection: {"accept": false}
// match on the literal, kernel-recovered destination IP drops the
// connection before any dial — the opaque-TCP twin of
// TestServeTransparent_TLS_ConnectionDeny_ConnectionDropped.
func TestServeTransparent_OpaqueTCP_ConnectionDeny_ConnectionDropped(t *testing.T) {
	dst := rawEchoServer(t)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q,"proto":"tcp"},"connection":{"accept":false}}]}`, dst.Addr().String())
	handler, _ := newTestHandler(t, ruleJSON)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	payload := []byte("\x00\x01not-http-not-tls-random-bytes\xff\xfe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q back, want the connection dropped with zero bytes (no splice for a denied connection)", got)
	}

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=denied") {
		t.Fatalf("outcome = %q, want denied", log)
	}
}

// TestServeTransparent_OpaqueTCP_HostHeaderConnectionDeny proves
// serveTransparentOpaqueMITM's own deny branch: the destination IP matches
// a plain mitm:true rule (so the opaque connection is parsed as HTTP), but
// the parsed request's Host header then matches a *different* rule that
// denies the connection outright — the message-phase re-lookup must still
// honor connection: {"accept": false}, not just the first, dst-IP-based
// LookupConn call.
func TestServeTransparent_OpaqueTCP_HostHeaderConnectionDeny(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should never be dialed for a denied connection")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	ruleJSON := fmt.Sprintf(`{"http":[
	  {"match":{"host":%q,"proto":"tcp"}},
	  {"match":{"host":"ads.example"},"connection":{"accept":false}}
	]}`, dst.Addr().String())
	handler, _ := newTestHandler(t, ruleJSON)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	hostHeader := fmt.Sprintf("ads.example:%d", dst.Port())
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %q back, want the connection dropped with zero bytes", got)
	}

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=denied") {
		t.Fatalf("outcome = %q, want denied", log)
	}
}

// TestServeTransparent_EgressDenied_FailsClosed proves egress policy
// still applies with a literal, kernel-recovered Dst: a client whose SNI
// matches a rule, but whose Dst falls in a denied CIDR, never reaches
// the origin at all.
func TestServeTransparent_EgressDenied_FailsClosed(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("origin should never be dialed when egress denies the destination")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":"sni.example"},"mitm":false}],
	  "egress":[{"cidr":%q,"action":"deny"}]}`, dst.Addr().String()+"/32")
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "sni.example", InsecureSkipVerify: true})
	tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("Handshake: want an error (connection dropped, egress denied), got success")
	}
}

// TestServeTransparent_TLS_AccessLogUsesSNI proves the access log for a
// transparently-intercepted TLS connection identifies it by the SNI
// hostname a rule actually matched on, not the kernel-recovered
// destination IP — logging the IP alone would make every domain behind
// the same load balancer or CDN edge indistinguishable in the log.
func TestServeTransparent_TLS_AccessLogUsesSNI(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "raw origin response")
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	ruleJSON := `{"http":[{"match":{"host":"sni.example"},"mitm":false}]}`
	handler, _ := newTestHandler(t, ruleJSON)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()

	tlsConn := tls.Client(raw, &tls.Config{ServerName: "sni.example", InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://sni.example/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	resp.Body.Close()

	log := buf.String()
	wantURL := "url=https://sni.example:" + strconv.Itoa(int(dst.Port()))
	if !strings.Contains(log, wantURL) {
		t.Fatalf("access log url field = %q, want it to name the SNI hostname, not the raw destination IP (%s): %q", wantURL, dst.Addr(), log)
	}
	// dst= is expected to carry the resolved IP (see
	// TestHttp1Handler_AccessLogIncludesResolvedDst) — only url= must not.
	if strings.Contains(log, "url=https://"+dst.Addr().String()) {
		t.Fatalf("access log url field used the raw destination IP instead of the SNI hostname: %q", log)
	}
}

// TestServeTransparent_HTTP_EmptyConnectionLogged proves a connection that
// closes before sending a single byte — the common, harmless case of
// connection racing (e.g. an iOS client's Happy Eyeballs opening several
// TCP connections and aborting every loser) or a plain TCP health check —
// logs the distinct "empty-connection" outcome, not "invalid-request",
// which would wrongly suggest the client sent something malformed.
func TestServeTransparent_HTTP_EmptyConnectionLogged(t *testing.T) {
	dst := mustAddrPort(t, "203.0.113.10:443")
	handler, _ := newTestHandler(t, `{"http":[{"match":{}}]}`)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close() // no bytes ever written — exactly a raced/aborted connection

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=empty-connection") {
		t.Fatalf("outcome = %q, want empty-connection", log)
	}
	if strings.Contains(log, "outcome=invalid-request") {
		t.Fatalf("a connection with zero bytes sent was logged as invalid-request, not empty-connection: %q", log)
	}
}

// TestServeTransparent_HTTP_GarbageNoMatchingRuleFailsClosed proves
// traffic that's neither TLS nor HTTP (garbage bytes that never form a
// valid header block) still fails closed when no rule permits it as
// opaque TCP — a specific-host rule that doesn't match the literal
// destination IP is exactly a no-match, same as ordinary HTTP/HTTPS
// traffic with no applicable rule.
func TestServeTransparent_HTTP_GarbageNoMatchingRuleFailsClosed(t *testing.T) {
	dst := mustAddrPort(t, "203.0.113.10:443")
	handler, _ := newTestHandler(t, `{"http":[{"match":{"host":"sni.example"},"mitm":false}]}`)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Write([]byte("not an http request at all\r\n"))
	conn.Close()

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=no-match") {
		t.Fatalf("outcome = %q, want no-match", log)
	}
}

// TestServeTransparent_OpaqueTCP_Splice proves the core claim: a
// transparently-intercepted connection that's neither a valid TLS
// ClientHello nor a valid HTTP request — like Telegram's MTProto
// "obfuscated" transport, deliberately random-looking bytes with no SNI
// and no Host header — still gets policy-controlled raw (mitm:false)
// passthrough when an explicit proto:"tcp" rule allows it, matched on the
// literal destination IP (there's no other signal available). The origin
// is a bare TCP echo server (no HTTP, no TLS) to prove the splice is
// byte-perfect, not just "some connection happened".
func TestServeTransparent_OpaqueTCP_Splice(t *testing.T) {
	dst := rawEchoServer(t)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q,"proto":"tcp"},"mitm":false}]}`, dst.Addr().String())
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("\x00\x01not-http-not-tls-random-bytes\xff\xfe")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed back %q, want %q (splice was not byte-perfect)", got, payload)
	}
}

// TestServeTransparent_OpaqueTCP_NoMatch_FailsClosed proves opaque TCP
// passthrough is opt-in per destination, not a blanket fallback: absent a
// proto:"tcp" rule, non-HTTP/non-TLS traffic still fails closed exactly
// like today.
func TestServeTransparent_OpaqueTCP_NoMatch_FailsClosed(t *testing.T) {
	dst := rawEchoServer(t)
	handler, _ := newTestHandler(t, `{"http":[{"match":{"host":"sni.example"},"mitm":false}]}`)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("\x00\x01not-http-not-tls\xff"))
	conn.(*net.TCPConn).CloseWrite()

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=no-match") {
		t.Fatalf("outcome = %q, want no-match", log)
	}
}

// TestServeTransparent_OpaqueTCP_MITMTrueNonHTTPFailsClosed proves a rule
// matching non-TLS traffic with mitm:true (or mitm omitted, defaulting to
// it) attempts an HTTP parse — that's what mitm:true on this path means,
// see serveTransparentOpaque's doc comment — and if the traffic genuinely
// isn't HTTP either, fails closed rather than silently downgrading to a
// raw splice the operator didn't ask for. The connection is not spliced;
// the origin never sees anything.
func TestServeTransparent_OpaqueTCP_MITMTrueNonHTTPFailsClosed(t *testing.T) {
	dst := rawEchoServer(t)
	// mitm omitted -> defaults true.
	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q,"proto":"tcp"}}]}`, dst.Addr().String())
	handler, _ := newTestHandler(t, ruleJSON)
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("\x00\x01not-http-not-tls\xff"))
	conn.(*net.TCPConn).CloseWrite()

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=invalid-request") {
		t.Fatalf("outcome = %q, want invalid-request", log)
	}
}

// rawEchoServer is a bare TCP server that echoes back whatever it reads —
// no HTTP, no TLS — standing in for an opaque, non-HTTP(S) protocol's
// origin (e.g. Telegram's MTProto). Proves a splice is byte-perfect, not
// just "some bytes came back".
func rawEchoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return mustAddrPort(t, ln.Addr().String())
}

// TestServeTransparent_ClientReadTimeoutLogged proves a transparently-
// intercepted connection that never delivers a complete ClientHello/
// request within ClientReadTimeout gets "client-read-timeout", distinct
// from "empty-connection" (which requires the peer to actually close/
// reset — here the connection is deliberately left open with nothing
// sent, so only the deadline can end it).
func TestServeTransparent_ClientReadTimeoutLogged(t *testing.T) {
	dst := mustAddrPort(t, "203.0.113.10:443")
	handler, _ := newTestHandler(t, `{"http":[{"match":{}}]}`)
	handler.ClientReadTimeout = 50 * time.Millisecond
	buf := &syncBuffer{}
	handler.Logger = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	log := waitForSubstring(t, buf, "outcome=")
	if !strings.Contains(log, "outcome=client-read-timeout") {
		t.Fatalf("outcome = %q, want client-read-timeout", log)
	}
}

// halfCloseProbeServer accepts one connection, writes a fixed message,
// half-closes its write side (but keeps reading), and reports whatever it
// eventually read back on receivedCh. Used to prove relay() correctly
// propagates a peeked/replayed connection's half-close to the other side
// as a read EOF, not just an eventual full close.
func halfCloseProbeServer(t *testing.T) (addr netip.AddrPort, receivedCh <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("origin says hi"))
		conn.(*net.TCPConn).CloseWrite()
		got, _ := io.ReadAll(conn)
		ch <- got
	}()
	return mustAddrPort(t, ln.Addr().String()), ch
}

// TestServeTransparent_TLS_HalfClosePropagates proves relay()'s
// half-close optimization actually reaches the client through the Replay
// wrapper (a *replayConn) every transparent-mode mitm:false splice goes
// through — embedding net.Conn (an interface) does not promote
// CloseWrite on its own (Go only promotes methods the embedded field's
// declared TYPE has, not ones the concrete value underneath happens to
// implement). Without replayConn's own CloseWrite, relay's closeWrite
// helper falls back to a FULL Close() the moment the origin's send
// direction finishes — which still produces a clean-looking EOF on the
// client's read (so a test that only checks "did I get EOF" can't tell
// the two apart), but severs the client's own still-valid ability to
// keep sending, exactly the shape that breaks a bidirectional protocol
// like Telegram's MTProto: the origin sends an initial chunk, then the
// client's own in-flight/pending send gets cut out from under it. The
// real proof is whether a write after the origin's half-close still
// succeeds and actually reaches the origin.
//
// (prependConn — the analogous wrapper for the new opaque-TCP
// passthrough — gets the identical fix, but isolating it the same way
// isn't possible: entering that path at all requires the client to
// already have closed/reset, so there's no still-open direction left to
// prove a write survives through.)
func TestServeTransparent_TLS_HalfClosePropagates(t *testing.T) {
	dst, receivedCh := halfCloseProbeServer(t)
	ruleJSON := `{"http":[{"match":{"host":"sni.example"},"mitm":false}]}`
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runTransparentProxy(t, handler, session.TransportRedirect, dst)

	// Captured via a real tls.Client Handshake over an in-memory pipe, not
	// driven live over the test's own connection: a live Handshake() reads
	// from its net.Conn internally, which would race directly reading the
	// same raw socket below — whichever read wins steals the origin's
	// bytes from the other. The raw origin here never completes a TLS
	// handshake anyway (mitm:false splices the TCP connection through
	// untouched regardless of what travels over it), so there's nothing
	// for a live Handshake() to complete against; only the ClientHello
	// bytes it wrote are needed.
	hello := captureClientHello(t, "sni.example")

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read exactly what the origin sent before it half-closed — proves the
	// forward direction relayed correctly, same as the ordinary splice
	// test. Not the interesting part of this test.
	raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len("origin says hi"))
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "origin says hi" {
		t.Fatalf("got %q, want \"origin says hi\"", buf)
	}

	// The origin only half-closed (halfCloseProbeServer keeps reading) —
	// the client's own connection must still be writable. A write here
	// failing is the actual signature of the bug: mitmania fully closed
	// the connection out from under the client instead of half-closing
	// just the direction that finished.
	followup := []byte("client followup")
	if _, err := raw.Write(followup); err != nil {
		t.Fatalf("client write after the origin's half-close failed — the connection was fully closed instead of half-closed: %v", err)
	}
	raw.(*net.TCPConn).CloseWrite()

	select {
	case got := <-receivedCh:
		// got is everything the origin ever read, which — TCP being
		// full-duplex — includes the ClientHello bytes relayed to it
		// earlier too; only the tail (whether the followup actually
		// arrived at all) is what this test is proving.
		if !bytes.HasSuffix(got, followup) {
			t.Fatalf("origin never received the client's followup after the origin's own half-close (got %d bytes, want it to end with %q)", len(got), followup)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("origin never finished reading the client's followup")
	}
}

// captureClientHello drives a real tls.Client Handshake over an in-memory
// net.Pipe and returns exactly the ClientHello bytes it wrote — for a test
// that needs genuine ClientHello bytes to send over a different
// connection without a live tls.Conn also reading that connection
// concurrently.
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tls.Client(client, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	}()
	buf := make([]byte, 4096)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("capture ClientHello: %v", err)
	}
	server.Close()
	client.Close()
	<-done
	return buf[:n]
}

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
// explicit client.
func TestServeTransparent_HTTP_HostHeaderMatch(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host seen: %s", r.Host)
	}))
	defer origin.Close()
	dst := mustAddrPort(t, origin.Listener.Addr().String())

	ruleJSON := `{"http":[{"match":{"host":"host.example"}}]}`
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

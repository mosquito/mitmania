package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"mitmania/internal/flowsink"
	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/storage"
)

// runProxy starts an HTTPProxyAcceptor + Dispatcher + Http1Handler on a
// loopback TCP listener and returns its address.
func runProxy(t *testing.T, handler *Http1Handler) (addr string) {
	t.Helper()
	return runProxyWithDialer(t, handler, NewUpstreamDialer(5*time.Second, 1))
}

// runProxyWithDialer is runProxy with an explicit UpstreamDialer, for tests
// that need to control connect timeout/retry behavior.
func runProxyWithDialer(t *testing.T, handler *Http1Handler, dialer UpstreamDialer) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	acc := session.NewHTTPProxyAcceptor(ln, "http_proxy")
	disp := &Dispatcher{Selector: &Selector{Default: handler}, Dialer: dialer}

	go func() {
		for {
			sess, err := acc.Accept()
			if err != nil {
				return
			}
			go disp.Handle(context.Background(), sess)
		}
	}()
	t.Cleanup(func() { acc.Close() })

	return ln.Addr().String()
}

// testPermissiveDefault is a rules/default table that covers the
// full v4/v6 address space with empty http[] (so it never matches a
// connection on its own) but allow-everything egress — the same shape
// main's EnsureDefault seeds a fresh cluster with. Test rule files can
// then keep omitting "egress" entirely and inherit "allow everything",
// matching this suite's pre-existing expectations, without every test
// needing to author its own egress[] list.
const testPermissiveDefault = `{
	"0.0.0.0/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]},
	"::/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"},{"cidr":"::/0","action":"allow"}]}
}`

// newTestHandler builds a handler backed by a fresh CertFactory and a
// RuleEngine whose store holds ruleJSON as the 127.0.0.1 client's rule
// file (all test connections originate from the loopback interface). An
// empty ruleJSON leaves that client with no file at all, i.e. it resolves
// via testPermissiveDefault instead, matching the old "no file ->
// empty ruleset" semantics as closely as a two-kind addressing model
// allows. Returns the handler alongside its CertFactory's root CA PEM —
// callers must use this PEM as the client's trust root, not an
// independently-generated one, since the root CA key is random per
// newTestFactory call.
func newTestHandler(t *testing.T, ruleJSON string) (*Http1Handler, []byte) {
	t.Helper()
	factory, ca := newTestFactory(t)
	caPEM := pemEncodeCert(ca.Cert.Raw)

	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	store := rules.NewRuleStore(st)
	if err := store.SaveDefault(context.Background(), []byte(testPermissiveDefault)); err != nil {
		t.Fatalf("store.SaveDefault: %v", err)
	}
	if ruleJSON != "" {
		if err := store.Save(context.Background(), netip.MustParseAddr("127.0.0.1"), []byte(ruleJSON)); err != nil {
			t.Fatalf("store.Save: %v", err)
		}
	}

	return &Http1Handler{
		TLS:                 &TLSService{Factory: factory},
		Rules:               rules.NewRuleEngine(store),
		CAPEM:               caPEM,
		HeaderLimit:         64 << 10,
		BodyWindow:          64 << 10,
		HTTP2ConnectTimeout: 5 * time.Second,
		HTTP2ConnectTries:   3,
		HTTP2ReadTimeout:    5 * time.Second,
	}, caPEM
}

// newHappyPathHandler is newTestHandler with a catch-all permissive rule
// (match everything, default mitm:true, no mutation) so existing
// happy-path scenarios keep working without every test needing to author
// its own rule file.
func newHappyPathHandler(t *testing.T) (*Http1Handler, []byte) {
	return newTestHandler(t, `{"http":[{"match":{}}]}`)
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// proxyHTTPClient builds an http.Client that routes all requests through
// the mitmania proxy at proxyAddr and trusts rootPEM for TLS verification.
func proxyHTTPClient(t *testing.T, proxyAddr string, rootPEM []byte) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if rootPEM != nil && !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func TestHTTP1Handler_ConnectRoundTrip(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	// origin.URL is already "https://127.0.0.1:PORT" — httptest's default
	// cert covers the 127.0.0.1 IP SAN, so no DNS/hosts trickery needed to
	// exercise a real CONNECT + TLS round trip through the proxy.
	resp, err := client.Get(origin.URL + "/hi")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if want := "hello from origin, path=/hi"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func TestHTTP1Handler_ServesCAPEM(t *testing.T) {
	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	wantBlock, _ := pem.Decode(caPEM)
	want, err := x509.ParseCertificate(wantBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.Get("http://" + proxyAddr + "/ca.pem")
	if err != nil {
		t.Fatalf("GET /ca.pem: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("body is not a PEM certificate: %s", body)
	}
	got, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("served cert != root CA cert")
	}
}

// TestHTTP1Handler_CAPEMDisabledGives404 covers writeCAPEM's nil branch
// (and, transitively, writeSimpleResponse — otherwise entirely untested):
// a node with no CAPEM configured (CAPEM disables the self-directed
// endpoint entirely, per its own doc comment) must answer GET /ca.pem with
// a plain 404, not serve a stale/empty cert or crash.
func TestHTTP1Handler_CAPEMDisabledGives404(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	handler.CAPEM = nil
	proxyAddr := runProxy(t, handler)

	resp, err := http.Get("http://" + proxyAddr + "/ca.pem")
	if err != nil {
		t.Fatalf("GET /ca.pem: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "Not Found\n" {
		t.Fatalf("body = %q, want %q", body, "Not Found\n")
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
}

// TestHTTP1Handler_FlowCountersTrackConnectionsAndRequests covers the
// h.Flow != nil branches in Serve and handleOneRequest: with a real
// flowsink.Counters attached, a single request/response round trip must be
// reflected in its counters (conns accepted, conns no longer active,
// requests served) — the only real FlowSink implementation, backing the
// control API's /stats.
func TestHTTP1Handler_FlowCountersTrackConnectionsAndRequests(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	handler, _ := newHappyPathHandler(t)
	counters := &flowsink.Counters{}
	handler.Flow = counters
	proxyAddr := runProxy(t, handler)
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	// A raw tunnel closed explicitly, rather than an http.Client (which
	// pools/keeps the proxy connection alive for reuse) — ConnsActive only
	// drops once the proxy's client-facing TCP connection actually closes,
	// so a pooled connection would never let this test observe that.
	tunnel := connectThroughProxy(t, proxyAddr, target)
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	tunnel.Close()

	deadline := time.Now().Add(2 * time.Second)
	var snap flowsink.Snapshot
	for time.Now().Before(deadline) {
		snap = counters.Snapshot()
		if snap.ConnsAccepted >= 1 && snap.Requests >= 1 && snap.ConnsActive == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if snap.ConnsAccepted < 1 {
		t.Errorf("ConnsAccepted = %d, want >= 1", snap.ConnsAccepted)
	}
	if snap.Requests < 1 {
		t.Errorf("Requests = %d, want >= 1", snap.Requests)
	}
	if snap.ConnsActive != 0 {
		t.Errorf("ConnsActive = %d, want 0 (the connection closed with the response)", snap.ConnsActive)
	}
}

// TestHTTP1Handler_MissingHostHeaderInTunnel_Misdirected covers
// requestURL's host=="" fallback (falling back to connIn.Host for logging)
// together with handleOneRequest's misdirected-authority rejection: an
// HTTP/1.0 request with no Host header at all inside an already-established
// mitm:true tunnel has an empty req.Host, which can never satisfy
// authorityMatches — this must render as 421, not panic or misattribute the
// request to the tunnel's own authority.
func TestHTTP1Handler_MissingHostHeaderInTunnel_Misdirected(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; a request with no Host header should have been rejected as misdirected")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
}

// TestServeAbsoluteForm_DNSFailure is the absolute-form twin of
// TestServeConnect_DNSFailure_ConnectResponseCarries523 (errpages_test.go):
// same resolve-phase failure, different error-delivery mechanic (a direct
// response instead of a CONNECT response).
func TestServeAbsoluteForm_DNSFailure(t *testing.T) {
	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get("http://this-host-does-not-exist.invalid/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 523 {
		t.Fatalf("status = %d, want 523 (Origin Is Unreachable)", resp.StatusCode)
	}
}

// TestHTTP1Handler_ResponseStatusAndBodyOverride covers the
// rri.StatusOverride/rri.BodyOverride branches: status.set and body.replace
// are the only response-phase actions that stage a full replacement rather
// than mutating headers in place, so the client must see the overridden
// status/body — including a recomputed Content-Length — not the origin's
// own.
func TestHTTP1Handler_ResponseStatusAndBodyOverride(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "original body from origin")
	}))
	defer origin.Close()

	ruleJSON := `{"http":[{"match":{},
	  "response":[
	    {"action":"status.set","params":{"status":201}},
	    {"action":"body.replace","params":{"body":"replaced body"}}
	  ]
	}]}`
	handler, caPEM := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (status.set override)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "replaced body" {
		t.Fatalf("body = %q, want %q (body.replace override)", body, "replaced body")
	}
	if got := resp.ContentLength; got != int64(len("replaced body")) {
		t.Fatalf("ContentLength = %d, want %d (recomputed for the replacement body)", got, len("replaced body"))
	}
}

// TestServeConnect_ClientRejectsRealCert_HandshakeFails covers
// terminateFailed's PhaseHandshake branch: Terminate's upstream dial and
// cert clone both succeed, but the client's own handshake fails (here,
// because the client doesn't trust mitmania's root CA at all) — at that
// point the client's TLS record-layer state may already be desynced, so
// terminateFailed must NOT attempt anything further (no fallback handshake
// on a connection whose TLS state is unknown), just log and end the
// connection. This is the "a client that won't trust our leaf" security
// case: the proxy must fail closed, not retry with a different cert over
// the same possibly-desynced connection.
func TestServeConnect_ClientRejectsRealCert_HandshakeFails(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; the client-side handshake should have failed first")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	handler, _ := newHappyPathHandler(t) // deliberately NOT using this handler's own CA below
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	// No RootCAs supplied and InsecureSkipVerify left false: the client
	// will reject mitmania's cloned leaf as untrusted, same as any real
	// browser that never installed the CA.
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err == nil {
		tlsConn.Close()
		t.Fatalf("client handshake unexpectedly succeeded against an untrusted cert")
	}
}

// TestServeConnect_TLSDialFail_ClientRejectsFallbackCert_LogsFallbackFailed
// covers terminateFailed's Fallback-itself-fails branch: the upstream
// TLS dial fails (PhaseDial, clientConn still pristine — same setup as
// errpages_test.go's TestServeConnect_TLSHandshakeFail_ServesFallbackPage),
// so a fallback handshake is attempted; but the client, again, doesn't
// trust mitmania's root CA, so even the fallback handshake fails. The
// connection must simply end — no infinite retry, no plaintext fallback,
// no page served over an untrusted channel.
func TestServeConnect_TLSDialFail_ClientRejectsFallbackCert_LogsFallbackFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // never speaks TLS — forces a PhaseDial failure
		}
	}()

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	target := ln.Addr().String()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}

	resp, conn := rawConnect(t, proxyAddr, target)
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200 (probe should have succeeded)", resp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: host}) // no RootCAs: rejects the fallback leaf too
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err == nil {
		tlsConn.Close()
		t.Fatalf("client handshake against the fallback cert unexpectedly succeeded")
	}
}

func TestHTTP1Handler_AbsoluteFormPlainHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain hello, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, nil)

	resp, err := client.Get(origin.URL + "/plain")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if want := "plain hello, path=/plain"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestHTTP1Handler_AbsoluteFormConnectionDenyGives403 covers
// serveAbsoluteForm's deny branch — the absolute-form twin of
// TestHTTP1Handler_ConnectionDenyGives403, proving the same
// connection: {"accept": false} short-circuit applies to plain-HTTP
// absolute-form requests, not just CONNECT tunnels.
func TestHTTP1Handler_AbsoluteFormConnectionDenyGives403(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; a denied connection should never be dialed")
	}))
	defer origin.Close()
	host, _, _ := net.SplitHostPort(origin.Listener.Addr().String())

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q},"connection":{"accept":false}}]}`, host)
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, nil)

	resp, err := client.Get(origin.URL + "/plain")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ERR_RULE_DENIED") {
		t.Fatalf("body does not look like the RuleDenied page:\n%s", body)
	}
}

// TestReadBoundedRequest_MalformedStartLine covers readBoundedRequest's
// http.ReadRequest failure branch specifically — distinct from the
// HeaderLimit trip (TestReadBoundedRequest_OversizedHeaders_SquidPage):
// here the header block is well within limit and properly terminated by a
// blank line, so boundNextHeaderBlock succeeds, but the bytes inside it
// aren't a parseable HTTP request line at all.
func TestReadBoundedRequest_MalformedStartLine(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "NOT A REQUEST LINE\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ERR_INVALID_REQ") {
		t.Fatalf("body missing ERR_INVALID_REQ: %s", body)
	}
}

func TestHTTP1Handler_RejectsOversizedHeaders(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	handler.HeaderLimit = 64 // tiny, deliberately
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Padding", string(make([]byte, 4096)))
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
}

// connectThroughProxy sends a raw CONNECT to proxyAddr for target and
// returns the still-plaintext tunnel conn positioned right after the
// "200 Connection Established" response — callers then speak TLS (or, for
// a mitm:false rule, plain bytes) over it directly.
func connectThroughProxy(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("ReadResponse (CONNECT): %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		t.Fatalf("unexpected buffered bytes after CONNECT response")
	}
	return conn
}

func TestHTTP1Handler_RequestAndResponseHeaderMutation(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Echo-Injected", r.Header.Get("X-Injected"))
		w.Header().Set("Location", "https://tracker.example/")
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	ruleJSON := `{"http":[{"match":{},
	  "request":[{"action":"header.add","params":{"X-Injected":"yes"}}],
	  "response":[{"action":"header.set","params":{"Location":null}}]
	}]}`
	handler, caPEM := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get(origin.URL + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Echo-Injected"); got != "yes" {
		t.Fatalf("Echo-Injected = %q, want yes (request header.add did not reach origin)", got)
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Fatalf("Location = %q, want deleted by response header.set null", got)
	}
}

func TestHTTP1Handler_RaiseShortCircuit(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; raise should have short-circuited before forwarding")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q,"path":"/blocked"},
	  "request":[{"action":"raise","params":{"http":403,"body":"Declined by policy"}}]}]}`, host)
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/blocked", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Declined by policy") || !strings.Contains(string(body), "ERR_ACCESS_DENIED") {
		t.Fatalf("body does not look like the Squid raise page:\n%s", body)
	}
}

func TestHTTP1Handler_BlockShortCircuit(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; block should have short-circuited before forwarding")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q},
	  "request":[{"action":"block"}]}]}`, host)
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	// block sends no response at all — the connection just ends.
	buf := make([]byte, 16)
	n, err := tlsConn.Read(buf)
	if err == nil {
		t.Fatalf("expected read error/EOF after block, got %d bytes: %q", n, buf[:n])
	}
}

func TestHTTP1Handler_NoMatchGives511(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; unmatched request should have gotten 511 before forwarding")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()

	// No rule file at all for this client -> empty ruleset -> no match.
	handler, _ := newTestHandler(t, "")
	proxyAddr := runProxy(t, handler)

	// Connection-phase default deny now happens before the reachability
	// probe or TLS handshake, so the 511 is the CONNECT response itself.
	resp, conn := rawConnect(t, proxyAddr, target)
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNetworkAuthenticationRequired {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNetworkAuthenticationRequired)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ERR_ACCESS_DENIED") {
		t.Fatalf("body does not look like the Squid no-match page:\n%s", body)
	}
}

// TestHTTP1Handler_ConnectionDenyGives403 covers serveConnect's deny
// branch: a connection: {"accept": false} match rejects the CONNECT
// outright, with a 403 ERR_RULE_DENIED response and the origin never
// dialed — distinct from an outright no-match (511) and from a mitm:true
// rule's later message-phase block (which requires TLS termination first).
func TestHTTP1Handler_ConnectionDenyGives403(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; a denied connection should never be dialed")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q},"connection":{"accept":false}}]}`, host)
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)

	resp, conn := rawConnect(t, proxyAddr, target)
	defer conn.Close()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ERR_RULE_DENIED") {
		t.Fatalf("body does not look like the RuleDenied page:\n%s", body)
	}
}

// TestHTTP1Handler_MessagePhaseNoMatchGives511 covers handleOneRequest's own
// no-match branch specifically (distinct from serveConnect's connection-
// phase no-match, already covered by TestHTTP1Handler_NoMatchGives511): a
// rule can match at the connection phase (host/port/proto — enough to
// authorize mitm:true and open the tunnel) while still not matching a
// given request's path/method at the message phase. That must fail closed
// with the same 511 as an outright connection-phase no-match, not silently
// forward an unauthorized request just because the tunnel itself was
// allowed.
func TestHTTP1Handler_MessagePhaseNoMatchGives511(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("origin was reached; the message-phase no-match should have short-circuited before forwarding")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	ruleJSON := `{"http":[{"match":{"path":"/allowed"}}]}`
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/not-allowed", nil)
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNetworkAuthenticationRequired {
		t.Fatalf("status = %d, want 511", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "ERR_ACCESS_DENIED") {
		t.Fatalf("body does not look like the Squid no-match page:\n%s", body)
	}
}

// TestHTTP1Handler_MitmFalseSplice asserts that a mitm:false rule bypasses
// TLS termination entirely: the client must see the origin's own real
// certificate, never a mitmania-signed clone.
func TestHTTP1Handler_MitmFalseSplice(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "raw origin response")
	}))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	ruleJSON := fmt.Sprintf(`{"http":[{"match":{"host":%q},"mitm":false}]}`, host)
	handler, _ := newTestHandler(t, ruleJSON)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	gotLeaf := tlsConn.ConnectionState().PeerCertificates[0]
	wantLeaf := origin.Certificate()
	if !gotLeaf.Equal(wantLeaf) {
		t.Fatalf("client saw a different cert than the origin's real one — mitm:false did not bypass TLS termination\ngot:  %v\nwant: %v", gotLeaf.Subject, wantLeaf.Subject)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
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

// closeAfterOneRequestHandler answers exactly one request with a normal,
// well-formed keep-alive-shaped response (no Connection: close — nothing
// about the response itself signals the socket is about to die), then
// forcibly closes the raw connection — simulating an origin's own idle
// timeout severing the connection between a proxy's keep-alive requests,
// entirely independent of anything the client/proxy did.
func closeAfterOneRequestHandler(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	body := fmt.Sprintf("response for %s", r.URL.Path)
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

// TestHTTP1Handler_H1UpstreamReconnectsAfterOriginClosesConnection is a
// regression/behavior test for h1RoundTripper's redial logic (roundtrip.go)
// wired through the real CONNECT/mitm:true path (http1.go's own redial
// closure, "return dialer.DialTLS(...)"): the proxy's upstream connection to
// origin is shared across every keep-alive request on the client's tunnel,
// and an origin can silently close its end between requests (idle timeout,
// among other things) with no signal to the proxy beyond the next write/read
// failing. A GET is idempotent, so the proxy must transparently redial and
// complete the second request rather than surfacing an error to the client
// for a purely origin-side hiccup.
func TestHTTP1Handler_H1UpstreamReconnectsAfterOriginClosesConnection(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(closeAfterOneRequestHandler))
	defer origin.Close()

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	br := bufio.NewReader(tlsConn)

	for i, path := range []string{"/first", "/second"} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+target+path, nil)
		if err := req.Write(tlsConn); err != nil {
			t.Fatalf("GET #%d write: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("GET #%d ReadResponse: %v (the proxy should have transparently redialed to origin)", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("GET #%d ReadAll: %v", i, err)
		}
		want := "response for " + path
		if string(body) != want {
			t.Fatalf("GET #%d body = %q, want %q", i, body, want)
		}
	}
}

// TestHTTP1Handler_AbsoluteFormRedialsAfterOriginClosesConnection is
// TestHTTP1Handler_H1UpstreamReconnectsAfterOriginClosesConnection's
// absolute-form (plain HTTP, mitm not involved at all) twin — covers the
// same h1RoundTripper redial path reached through serveAbsoluteForm's own
// redial closure instead of serveConnect's.
func TestHTTP1Handler_AbsoluteFormRedialsAfterOriginClosesConnection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(closeAfterOneRequestHandler))
	defer origin.Close()

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer proxyConn.Close()
	br := bufio.NewReader(proxyConn)

	for i, path := range []string{"/first", "/second"} {
		req, _ := http.NewRequest(http.MethodGet, origin.URL+path, nil)
		// WriteProxy, not Write: this is a proxy request, so the request
		// line needs the absolute-form target (scheme+host), not origin-form
		// — otherwise the proxy can't tell what to look up requestURL.Host as
		// and rejects it as a malformed request.
		if err := req.WriteProxy(proxyConn); err != nil {
			t.Fatalf("GET #%d write: %v", i, err)
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("GET #%d ReadResponse: %v (the proxy should have transparently redialed to origin)", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("GET #%d ReadAll: %v", i, err)
		}
		want := "response for " + path
		if string(body) != want {
			t.Fatalf("GET #%d body = %q, want %q", i, body, want)
		}
	}
}

// wsEchoHandler completes a bare-minimum WebSocket-shaped handshake (101
// Switching Protocols, no real frame parsing) then echoes every byte read
// back verbatim — enough to prove a proxy in front of it preserves bytes
// exactly, without needing a real WebSocket implementation.
func wsEchoHandler(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		return
	}

	// net/http's own hijack handoff can leave bytes the client pipelined
	// right behind the request sitting in bufrw's buffer — drain those
	// before falling through to raw conn reads, same reasoning as
	// drainBuffered in http1.go.
	var reader io.Reader = conn
	if n := bufrw.Reader.Buffered(); n > 0 {
		buffered, _ := bufrw.Reader.Peek(n)
		reader = io.MultiReader(bytes.NewReader(append([]byte(nil), buffered...)), conn)
	}

	io.Copy(conn, reader)
}

// TestHTTP1Handler_WebSocketPassthroughByteExact drives an Upgrade
// request through the mitm:true path with a payload pipelined
// immediately behind it (in the same TLS write), so a correct
// implementation must be draining clientBR/upstreamBR's buffered bytes
// ("after headers, switch to a raw bidirectional pipe — zero
// buffering") rather than dropping or reordering them.
func TestHTTP1Handler_WebSocketPassthroughByteExact(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(wsEchoHandler))
	defer origin.Close()
	target := origin.Listener.Addr().String()
	host, _, _ := net.SplitHostPort(target)

	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	tunnel := connectThroughProxy(t, proxyAddr, target)
	defer tunnel.Close()
	tlsConn := tls.Client(tunnel, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	const payload = "PING-PAYLOAD-PIPELINED-RIGHT-BEHIND-THE-UPGRADE-REQUEST"
	reqBytes := "GET / HTTP/1.1\r\nHost: " + target + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := tlsConn.Write([]byte(reqBytes + payload)); err != nil {
		t.Fatalf("write upgrade request + pipelined payload: %v", err)
	}

	br := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echoed pipelined payload: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed payload = %q, want %q (bytes lost or reordered across the splice)", got, payload)
	}

	// Sanity: the pipe keeps working for bytes sent well after the
	// handshake too, not just ones that happened to be buffered already.
	const more = "more-data-after-handshake-completes"
	if _, err := tlsConn.Write([]byte(more)); err != nil {
		t.Fatalf("write post-handshake data: %v", err)
	}
	got2 := make([]byte, len(more))
	if _, err := io.ReadFull(br, got2); err != nil {
		t.Fatalf("read second echo: %v", err)
	}
	if string(got2) != more {
		t.Fatalf("second echo = %q, want %q", got2, more)
	}
}

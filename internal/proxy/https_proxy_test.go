package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"mitmania/internal/cert"
	"mitmania/internal/rules"
	"mitmania/internal/session"
	"mitmania/internal/storage"
)

// newHappyPathHandlerWithFactory is newHappyPathHandler but also returns
// the backing *cert.CertFactory — needed to mint the https-proxy listener's
// own self-cert (SelfCert isn't part of proxy.CertFactory, the narrow
// interface TLSService depends on) from the SAME root as handler.TLS.
func newHappyPathHandlerWithFactory(t *testing.T) (handler *Http1Handler, caPEM []byte, factory *cert.CertFactory) {
	t.Helper()
	factory, ca := newTestFactory(t)
	caPEM = pemEncodeCert(ca.Cert.Raw)

	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	store := rules.NewRuleStore(st)
	if err := store.SaveDefault(context.Background(), []byte(testPermissiveDefault)); err != nil {
		t.Fatalf("store.SaveDefault: %v", err)
	}
	if err := store.Save(context.Background(), netip.MustParseAddr("127.0.0.1"), []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	handler = &Http1Handler{
		TLS:                 &TLSService{Factory: factory},
		Rules:               rules.NewRuleEngine(store),
		CAPEM:               caPEM,
		HeaderLimit:         64 << 10,
		BodyWindow:          64 << 10,
		HTTP2ConnectTimeout: 5 * time.Second,
		HTTP2ConnectTries:   3,
		HTTP2ReadTimeout:    5 * time.Second,
	}
	return handler, caPEM, factory
}

// runHTTPSProxy mints a self-cert for name via factory — the SAME
// *cert.CertFactory backing handler.TLS, so the minted self-cert and any
// MITM'd leaf share one root — and starts a TLS-terminating
// HTTPProxyAcceptor + Dispatcher + handler on a loopback TCP listener,
// mirroring runProxy but for the --listen-https-proxy path.
func runHTTPSProxy(t *testing.T, handler *Http1Handler, factory *cert.CertFactory, names []string) (addr string) {
	t.Helper()
	leaf, err := factory.SelfCert(context.Background(), names)
	if err != nil {
		t.Fatalf("SelfCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	acc := session.NewHTTPProxyAcceptor(tlsLn, "https_proxy")
	disp := &Dispatcher{Selector: &Selector{Default: handler}, Dialer: NewUpstreamDialer(5*time.Second, 1)}

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

// connectThroughHTTPSProxy is connectThroughProxy (see http1_test.go) but
// dials the proxy itself over TLS first — the https-proxy listener speaks
// CONNECT identically to the plain listener once its own TLS leg is
// terminated, since both share the same HTTPProxyAcceptor/Dispatcher/
// Http1Handler pipeline.
func connectThroughHTTPSProxy(t *testing.T, proxyAddr string, proxyRootPEM []byte, proxyServerName, target string) net.Conn {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(proxyRootPEM) {
		t.Fatalf("failed to parse proxy root PEM")
	}
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{RootCAs: pool, ServerName: proxyServerName})
	if err != nil {
		t.Fatalf("tls.Dial proxy: %v", err)
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

func TestHTTPSProxy_ConnectRoundTripOverOwnTLS(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from origin, path=%s", r.URL.Path)
	}))
	defer origin.Close()

	handler, caPEM, factory := newHappyPathHandlerWithFactory(t)
	// "Internal Proxy" (space) is the friendly CN; "proxy.internal.example"
	// is the syntactically valid SAN a real TLS client actually verifies
	// against — mirrors the fix for the interop bug found via a live
	// openssl s_client/curl smoke test (a lone free-text CN produces an
	// empty SAN set no OpenSSL-based client can verify).
	const proxyServerName = "proxy.internal.example"
	proxyAddr := runHTTPSProxy(t, handler, factory, []string{"Internal Proxy", proxyServerName})

	target := origin.Listener.Addr().String()
	tunnel := connectThroughHTTPSProxy(t, proxyAddr, caPEM, proxyServerName, target)
	defer tunnel.Close()

	// The tunnel is the https-proxy listener's OWN TLS leg, already
	// terminated. What flows over it now is the MITM'd TLS leg to origin
	// (same as any plain-listener CONNECT tunnel, TestHTTP1Handler_
	// ConnectRoundTrip): mitmania clones origin's SAN set into a leaf
	// re-signed by ITS OWN root — the same root as the https-proxy
	// listener's own cert — not by origin's original (self-signed) key.
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse proxy root PEM")
	}
	originHost, _, _ := net.SplitHostPort(target)
	tlsConn := tls.Client(tunnel, &tls.Config{RootCAs: rootPool, ServerName: originHost})
	defer tlsConn.Close()

	req, err := http.NewRequest(http.MethodGet, "https://"+target+"/hi", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("req.Write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPSProxy_RejectsWrongServerName(t *testing.T) {
	handler, caPEM, factory := newHappyPathHandlerWithFactory(t)
	proxyAddr := runHTTPSProxy(t, handler, factory, []string{"Internal Proxy", "proxy.internal.example"})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse proxy root PEM")
	}
	conn, err := tls.Dial("tcp", proxyAddr, &tls.Config{RootCAs: pool, ServerName: "not-the-right-name"})
	if err == nil {
		conn.Close()
		t.Fatalf("tls.Dial with a mismatched ServerName unexpectedly succeeded")
	}
}

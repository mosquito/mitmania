package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rawConnect sends a raw CONNECT to proxyAddr for target and returns the
// parsed CONNECT response plus the still-open connection — unlike
// connectThroughProxy, it doesn't assume a 200, so callers can inspect a
// failure response directly.
func rawConnect(t *testing.T, proxyAddr, target string) (*http.Response, net.Conn) {
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
	return resp, conn
}

// TestServeConnect_UnreachableUpstream_ConnectResponseCarriesError is
// the "Explicit, pre-tunnel" error-delivery mechanic: a connect-phase
// failure (here, connection refused — nothing listens on the target port)
// surfaces as the CONNECT response's own status, not a silent drop after
// "200 Connection Established".
func TestServeConnect_UnreachableUpstream_ConnectResponseCarriesError(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	// Port 1 is privileged/unassigned — nothing should be listening there,
	// giving a reliable connection-refused across platforms/CI.
	resp, conn := rawConnect(t, proxyAddr, "127.0.0.1:1")
	defer conn.Close()

	if resp.StatusCode != 521 {
		t.Fatalf("CONNECT status = %d, want 521 (Web Server Is Down)", resp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "ERR_CONNECT_FAIL") {
		t.Fatalf("body missing ERR_CONNECT_FAIL: %s", body[:n])
	}
}

// TestServeConnect_DNSFailure_ConnectResponseCarries523 is the DNS-specific
// case of the same delivery mechanic — ".invalid" is IANA-reserved (RFC
// 2606) to never resolve.
func TestServeConnect_DNSFailure_ConnectResponseCarries523(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	resp, conn := rawConnect(t, proxyAddr, "this-host-does-not-exist.invalid:443")
	defer conn.Close()

	if resp.StatusCode != 523 {
		t.Fatalf("CONNECT status = %d, want 523 (Origin Is Unreachable)", resp.StatusCode)
	}
}

// TestServeConnect_TLSHandshakeFail_ServesFallbackPage is
// the "Over-TLS" error-delivery mechanic: the probe dial (plain TCP) succeeds — so
// the proxy commits to "200 Connection Established" — but the real
// upstream TLS handshake then fails (the "origin" here just accepts and
// closes, never speaking TLS at all). The proxy must still complete a TLS
// handshake with the client (using a fallback cert minted for the SNI
// alone, signed by our root) and serve the Squid-style error page inside
// that session, rather than a bare reset.
func TestServeConnect_TLSHandshakeFail_ServesFallbackPage(t *testing.T) {
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
			c.Close() // never speaks TLS — forces a handshake failure
		}
	}()

	handler, caPEM := newHappyPathHandler(t)
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

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse root PEM")
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: pool})
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake with fallback cert failed: %v", err)
	}

	// The fallback leaf's identity must be the SNI, signed by our real
	// root — a client that trusts our CA validates it exactly like any
	// other cloned leaf.
	leaf := tlsConn.ConnectionState().PeerCertificates[0]
	if leaf.Subject.CommonName != host {
		t.Fatalf("fallback leaf CommonName = %q, want %q", leaf.Subject.CommonName, host)
	}

	httpResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("ReadResponse over fallback session: %v", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != 525 {
		t.Fatalf("status = %d, want 525 (SSL Handshake Failed)", httpResp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := httpResp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "ERR_SECURE_CONNECT_FAIL") {
		t.Fatalf("body missing ERR_SECURE_CONNECT_FAIL: %s", body[:n])
	}
}

// TestServeAbsoluteForm_UnreachableUpstream verifies the plain-HTTP
// absolute-form path (the "Plain HTTP" error-delivery mechanic: direct
// response) gets the same classified error.
func TestServeAbsoluteForm_UnreachableUpstream(t *testing.T) {
	handler, caPEM := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)
	client := proxyHTTPClient(t, proxyAddr, caPEM)

	resp, err := client.Get("http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 521 {
		t.Fatalf("status = %d, want 521 (Web Server Is Down)", resp.StatusCode)
	}
}

// TestReadBoundedRequest_OversizedHeaders_SquidPage verifies the
// HeaderLimit trip now renders the Squid-style page (ERR_TOO_BIG),
// not a bare plain-text body.
func TestReadBoundedRequest_OversizedHeaders_SquidPage(t *testing.T) {
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "ERR_TOO_BIG") {
		t.Fatalf("body missing ERR_TOO_BIG (still the old plain-text page?): %s", body[:n])
	}
}

// TestServe_InvalidRequestShape_SquidPage verifies a request that's
// neither CONNECT, absolute-form, nor GET /ca.pem gets the Squid-style
// ERR_INVALID_REQ page.
func TestServe_InvalidRequestShape_SquidPage(t *testing.T) {
	handler, _ := newHappyPathHandler(t)
	proxyAddr := runProxy(t, handler)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Origin-form outside a CONNECT tunnel — not valid proxy request shape.
	if _, err := fmt.Fprintf(conn, "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
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
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "ERR_INVALID_REQ") {
		t.Fatalf("body missing ERR_INVALID_REQ: %s", body[:n])
	}
}

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"mitmania/internal/cert"
	"mitmania/internal/storage"
)

func newTestFactory(t *testing.T) (*cert.CertFactory, *cert.CA) {
	t.Helper()
	st, err := storage.NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}
	ca, err := cert.LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := cert.NewCertCache(st, ck, ca)
	return cert.NewCertFactory(ca, cache, cert.DetKeyDeriver{ClusterKey: ck}), ca
}

func TestUpstreamDialer_FetchesRealChain(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	dst := ts.Listener.Addr().String()
	conn, err := NewUpstreamDialer(5*time.Second, 1).DialTLS(context.Background(), "tcp", dst, "example.com")
	if err != nil {
		t.Fatalf("DialTLS: %v", err)
	}
	defer conn.Close()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		t.Fatalf("no peer certificates observed")
	}
	if len(chain[0].DNSNames) == 0 && chain[0].Subject.CommonName == "" {
		t.Fatalf("fetched leaf has no identity to speak of: %+v", chain[0])
	}
}

func TestTLSService_Terminate(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()
	dst := ts.Listener.Addr().String()

	// httptest's built-in test cert (net/http/internal/testcert) is issued
	// for "example.com" and 127.0.0.1.
	const sni = "example.com"

	factory, ca := newTestFactory(t)
	svc := &TLSService{Factory: factory}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})

	clientErr := make(chan error, 1)
	go func() { clientErr <- tlsClient.Handshake() }()

	result, err := svc.Terminate(context.Background(), serverConn, NewUpstreamDialer(5*time.Second, 1), dst, sni)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	defer result.Client.Close()
	defer result.Upstream.Close()

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if result.ALPN != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1", result.ALPN)
	}
	if len(result.Upstream.ConnectionState().PeerCertificates) == 0 {
		t.Fatalf("Upstream connection has no peer certificates")
	}

	// The client's view of the synthetic leaf must carry the real leaf's
	// identity (httptest's testcert), not our root's.
	clientState := tlsClient.ConnectionState()
	if len(clientState.PeerCertificates) == 0 {
		t.Fatalf("client observed no certificates from the synthetic handshake")
	}
	got := clientState.PeerCertificates[0]
	if got.Equal(ca.Cert) {
		t.Fatalf("client was served the root CA cert instead of a cloned leaf")
	}

	// tls.Conn.Close() blocks up to 5s writing close_notify if nothing
	// reads the other end of the pipe; drain in the background so the
	// deferred Close() calls above return promptly.
	go io.Copy(io.Discard, tlsClient)
}

// TestTLSService_Terminate_H2 verifies the ALPN plumbing: against an
// h2-capable origin, upstream negotiates h2, and the
// client-facing offer becomes conditional on that — a client that itself
// offers h2 gets it back.
func TestTLSService_Terminate_H2(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = ts.Config.TLSConfig
	ts.StartTLS()
	defer ts.Close()
	dst := ts.Listener.Addr().String()

	const sni = "example.com"

	factory, ca := newTestFactory(t)
	svc := &TLSService{Factory: factory}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		NextProtos: []string{"h2", "http/1.1"},
	})

	clientErr := make(chan error, 1)
	go func() { clientErr <- tlsClient.Handshake() }()

	result, err := svc.Terminate(context.Background(), serverConn, NewUpstreamDialer(5*time.Second, 1), dst, sni)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	defer result.Client.Close()
	defer result.Upstream.Close()

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if result.UpstreamALPN != "h2" {
		t.Fatalf("UpstreamALPN = %q, want h2", result.UpstreamALPN)
	}
	if result.ALPN != "h2" {
		t.Fatalf("ALPN = %q, want h2 (client offered h2 and upstream is h2)", result.ALPN)
	}

	go io.Copy(io.Discard, tlsClient)
}

// TestTLSService_Terminate_H2Upstream_H1Client verifies that when upstream
// negotiates h2 but the client's own offer is http/1.1-only (e.g. an older
// client), the client-facing leg still downgrades to http/1.1 rather than
// forcing h2 on a client that never asked for it.
func TestTLSService_Terminate_H2Upstream_H1Client(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ts.TLS = ts.Config.TLSConfig
	ts.StartTLS()
	defer ts.Close()
	dst := ts.Listener.Addr().String()

	const sni = "example.com"

	factory, ca := newTestFactory(t)
	svc := &TLSService{Factory: factory}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})

	clientErr := make(chan error, 1)
	go func() { clientErr <- tlsClient.Handshake() }()

	result, err := svc.Terminate(context.Background(), serverConn, NewUpstreamDialer(5*time.Second, 1), dst, sni)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	defer result.Client.Close()
	defer result.Upstream.Close()

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if result.UpstreamALPN != "h2" {
		t.Fatalf("UpstreamALPN = %q, want h2", result.UpstreamALPN)
	}
	if result.ALPN != "http/1.1" {
		t.Fatalf("ALPN = %q, want http/1.1 (client never offered h2)", result.ALPN)
	}

	go io.Copy(io.Discard, tlsClient)
}

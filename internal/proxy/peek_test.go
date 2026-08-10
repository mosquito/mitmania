package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestPeekClientHello(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientErr := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(clientConn, &tls.Config{
			ServerName:         "peek.example.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		clientErr <- tlsClient.Handshake()
	}()

	hello, err := PeekClientHello(serverConn)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if hello.ServerName != "peek.example.com" {
		t.Fatalf("ServerName = %q, want peek.example.com", hello.ServerName)
	}
	if len(hello.ALPN) != 2 || hello.ALPN[0] != "h2" || hello.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %v, want [h2 http/1.1]", hello.ALPN)
	}
	if len(hello.Raw) == 0 {
		t.Fatalf("Raw is empty")
	}

	// The peek aborts the handshake without ever writing to the real
	// connection, so the client is left blocked reading a ServerHello that
	// will never come. Closing unblocks it; we don't care about its error.
	clientConn.Close()
	<-clientErr
}

func TestPeekClientHello_NotTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		clientConn.Close()
	}()

	hello, err := PeekClientHello(serverConn)
	if err == nil {
		t.Fatalf("PeekClientHello: expected error for non-TLS input, got hello=%+v", hello)
	}
}

// TestPeekThenReplayHandshake exercises the full production sequence: peek
// a ClientHello without touching the network, then complete a *real*
// handshake over the same logical connection by replaying the captured
// bytes — proving the client never has to resend anything.
func TestPeekThenReplayHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverCert, ca := selfSignedTestCert(t, "replay.example.com")

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: "replay.example.com",
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- tlsClient.Handshake()
	}()

	hello, err := PeekClientHello(serverConn)
	if err != nil {
		t.Fatalf("PeekClientHello: %v", err)
	}
	if hello.ServerName != "replay.example.com" {
		t.Fatalf("ServerName = %q", hello.ServerName)
	}

	replayed := Replay(serverConn, hello.Raw)
	realServer := tls.Server(replayed, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := realServer.Handshake(); err != nil {
		t.Fatalf("real handshake over replayed conn: %v", err)
	}

	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	// Sanity: bytes actually flow both ways post-handshake.
	go func() {
		realServer.Write([]byte("pong"))
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, buf); err != nil {
		t.Fatalf("read after handshake: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q, want pong", buf)
	}
}

func TestReplay(t *testing.T) {
	a, b := net.Pipe()
	go func() {
		b.Write([]byte("REST"))
		b.Close()
	}()
	wrapped := Replay(a, []byte("PRE-"))
	got, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "PRE-REST" {
		t.Fatalf("got %q, want PRE-REST", got)
	}
}

// selfSignedTestCert builds a throwaway self-signed leaf for tests that
// need a real (non-mitmania) TLS server identity.
func selfSignedTestCert(t *testing.T, dnsName string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert
}

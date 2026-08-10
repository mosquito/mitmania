package session

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestSessionClientKeyDefaultsToLoopback(t *testing.T) {
	var s Session // zero value: no Client set (e.g. a unix-socket accept)
	if got := s.ClientKey(); got != loopback {
		t.Fatalf("ClientKey() = %v, want loopback (%v)", got, loopback)
	}
}

func TestSessionClientKeyUsesRealAddr(t *testing.T) {
	addr := netip.MustParseAddrPort("10.0.0.5:12345")
	s := Session{Client: addr}
	if got := s.ClientKey(); got != addr.Addr() {
		t.Fatalf("ClientKey() = %v, want %v", got, addr.Addr())
	}
}

func TestHTTPProxyAcceptor_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	acc := NewHTTPProxyAcceptor(ln, "http_proxy")
	defer acc.Close()

	go func() {
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			conn.Close()
		}
	}()

	sess, err := acc.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer sess.Conn.Close()

	if sess.Transport != TransportExplicit {
		t.Fatalf("Transport = %v, want %v", sess.Transport, TransportExplicit)
	}
	if !sess.Client.IsValid() || sess.Client.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("Client = %v, want a valid 127.0.0.1 addr", sess.Client)
	}
	if sess.Acceptor != "http_proxy" {
		t.Fatalf("Acceptor = %q, want %q", sess.Acceptor, "http_proxy")
	}
}

func TestHTTPProxyAcceptor_Unix(t *testing.T) {
	// Deliberately not t.TempDir(): on macOS its path (under
	// $TMPDIR/go-buildXXXX/TestName.../001/...) routinely exceeds the
	// ~104-byte sun_path limit for AF_UNIX addresses, failing bind(2) with
	// EINVAL. /tmp is short and available on every platform this runs on.
	sockPath := fmt.Sprintf("/tmp/mitmania-test-%d.sock", os.Getpid())
	os.Remove(sockPath)
	t.Cleanup(func() { os.Remove(sockPath) })

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	acc := NewHTTPProxyAcceptor(ln, "http_proxy")
	defer acc.Close()

	go func() {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			conn.Close()
		}
	}()

	sess, err := acc.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer sess.Conn.Close()

	// unix sockets carry no usable peer address; Client stays zero-value
	// and ClientKey() falls back to loopback (per-client rule lookup by
	// source IP doesn't apply to a connection with no source IP).
	if sess.Client.IsValid() {
		t.Fatalf("Client = %v, want zero value for a unix-socket accept", sess.Client)
	}
	if got := sess.ClientKey(); got != loopback {
		t.Fatalf("ClientKey() = %v, want loopback", got)
	}
}

func TestTransportString(t *testing.T) {
	if got := TransportExplicit.String(); got != "explicit" {
		t.Fatalf("String() = %q, want explicit", got)
	}
	if got := Transport(99).String(); got != "unknown" {
		t.Fatalf("String() = %q, want unknown", got)
	}
}

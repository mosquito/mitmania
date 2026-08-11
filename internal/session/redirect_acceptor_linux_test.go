//go:build linux

package session

import (
	"net"
	"testing"
)

// TestRedirectAcceptor_NoNATFailsClosed proves the real, always-runnable
// part of SO_ORIGINAL_DST recovery without needing NAT rules or root: a
// connection that was never actually redirected has no original
// destination to recover, and originalDst must report that clearly
// rather than returning a garbage/zero address that would silently
// mismatch every rule. Real nftables-redirected traffic (needing root
// and a REDIRECT rule) is exercised in a live Docker smoke test, not
// here — see the plan's verification notes.
func TestRedirectAcceptor_NoNATFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a, err := NewRedirectAcceptor(ln, "redirect")
	if err != nil {
		t.Fatalf("NewRedirectAcceptor: %v", err)
	}

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := a.Accept()
	if err == nil {
		sess.Conn.Close()
		t.Fatal("Accept: want error for a non-NAT'd connection, got nil")
	}
}

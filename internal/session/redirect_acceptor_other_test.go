//go:build !linux

package session

import (
	"net"
	"testing"
)

// TestRedirectAcceptor_NotSupportedOffLinux proves the non-Linux build's
// constructor fails clearly rather than silently no-op'ing — a caller
// wiring up --listen-http-redirect on an unsupported platform must get a
// startup error, not a listener that never resolves a real destination.
func TestRedirectAcceptor_NotSupportedOffLinux(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a, err := NewRedirectAcceptor(ln, "redirect")
	if err == nil {
		t.Fatal("NewRedirectAcceptor: want error on this platform, got nil")
	}
	if a != nil {
		t.Fatalf("NewRedirectAcceptor: want nil Acceptor on error, got %+v", a)
	}
}

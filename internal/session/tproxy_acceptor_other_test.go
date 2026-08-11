//go:build !linux

package session

import "testing"

// TestTProxyAcceptor_NotSupportedOffLinux mirrors
// TestRedirectAcceptor_NotSupportedOffLinux for the TPROXY path: both the
// listen step and the constructor must fail clearly on an unsupported
// platform.
func TestTProxyAcceptor_NotSupportedOffLinux(t *testing.T) {
	ln, err := ListenTProxy("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatal("ListenTProxy: want error on this platform, got nil")
	}
	if ln != nil {
		t.Fatalf("ListenTProxy: want nil listener on error, got %+v", ln)
	}

	a, err := NewTProxyAcceptor(nil, "tproxy")
	if err == nil {
		t.Fatal("NewTProxyAcceptor: want error on this platform, got nil")
	}
	if a != nil {
		t.Fatalf("NewTProxyAcceptor: want nil Acceptor on error, got %+v", a)
	}
}

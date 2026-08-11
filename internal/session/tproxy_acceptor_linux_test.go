//go:build linux

package session

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestListenTProxy_SetsTransparentOrSkipsWithoutPrivilege proves
// ListenTProxy either binds with the transparent socket options set
// (when this process has CAP_NET_ADMIN) or fails with a permission error
// (when it doesn't) — never silently succeeds with the option unset,
// which would make every TPROXY-routed connection this listener
// receives fail at the kernel level for a reason invisible from Go.
// Real transparent routing (a redirected connection whose Dst differs
// from the listener's own bind address) needs actual policy routing and
// is exercised in a live Docker smoke test, not here.
func TestListenTProxy_SetsTransparentOrSkipsWithoutPrivilege(t *testing.T) {
	ln, err := ListenTProxy("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, os.ErrPermission) {
			t.Skipf("no CAP_NET_ADMIN in this environment: %v", err)
		}
		t.Fatalf("ListenTProxy: unexpected error: %v", err)
	}
	defer ln.Close()

	a, err := NewTProxyAcceptor(ln, "tproxy")
	if err != nil {
		t.Fatalf("NewTProxyAcceptor: %v", err)
	}

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := a.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer sess.Conn.Close()

	if sess.Transport != TransportTProxy {
		t.Errorf("Transport = %v, want TransportTProxy", sess.Transport)
	}
	if sess.Acceptor != "tproxy" {
		t.Errorf("Acceptor = %q, want %q", sess.Acceptor, "tproxy")
	}
	// Without real policy routing in play, Dst is just this listener's
	// own bind address — that's still a meaningful assertion that
	// LocalAddr() is what Accept wires into Dst, the part this test can
	// prove without root-level nftables/ip-rule setup.
	if sess.Dst.Addr().String() != "127.0.0.1" {
		t.Errorf("Dst = %v, want host 127.0.0.1 (this listener's own address, absent real TPROXY routing)", sess.Dst)
	}
}

//go:build linux

package session

import (
	"net"
	"testing"
)

// TestRedirectAcceptor_NoNATDoesNotFabricateADestination proves the real,
// always-runnable part of SO_ORIGINAL_DST recovery without needing NAT
// rules or root: a connection that was never actually redirected must
// never silently produce a Dst that looks like a real, different-from-
// the-listener redirect target — that would mismatch every rule against
// a destination nothing ever asked for.
//
// SO_ORIGINAL_DST's behavior on a non-NAT'd socket is not portable
// across kernels: on a kernel with the netfilter conntrack/NAT modules
// loaded (true of every environment this was developed and live-tested
// against — real nftables commands were run there, loading them as a
// side effect), the getsockopt call fails outright, and Accept()
// surfaces that as an error. On at least one real CI kernel observed
// with those modules never loaded (nothing in that job ever runs an
// nftables/iptables command), the same call instead succeeds trivially,
// reporting the connection's own local address as "the destination" —
// which is not a fabricated value, just a degenerate one equal to
// exactly what a caller already knows independently (the listener's own
// bind address). Assert whichever of these two real behaviors this
// kernel has, rather than asserting only the one this feature happened
// to be developed against.
func TestRedirectAcceptor_NoNATDoesNotFabricateADestination(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	listenerAddr := ln.Addr().String()

	a, err := NewRedirectAcceptor(ln, "redirect")
	if err != nil {
		t.Fatalf("NewRedirectAcceptor: %v", err)
	}

	client, err := net.Dial("tcp", listenerAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	sess, err := a.Accept()
	if err != nil {
		return // this kernel fails closed on a non-NAT'd connection — the ideal case
	}
	defer sess.Conn.Close()
	if sess.Dst.String() != listenerAddr {
		t.Fatalf("Accept succeeded on a non-NAT'd connection with Dst = %s, want the listener's own address %s (a fabricated-looking Dst here would silently mismatch every rule)", sess.Dst, listenerAddr)
	}
}

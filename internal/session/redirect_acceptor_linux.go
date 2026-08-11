//go:build linux

package session

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// RedirectAcceptor accepts connections on a REDIRECT (iptables/nftables
// DNAT) listener and recovers the true pre-NAT destination via the
// SO_ORIGINAL_DST socket option — the kernel only tracks this under NAT
// redirection, unlike TPROXY, which needs no getsockopt at all (see
// TProxyAcceptor: there, the accepted connection's own local address
// already is the real destination).
type RedirectAcceptor struct {
	ln   net.Listener
	name string
}

// NewRedirectAcceptor wraps an already-bound listener. Ordinary
// net.Listen is enough here — unlike TPROXY, REDIRECT needs no special
// socket option on the listening socket itself, only on each accepted
// connection.
func NewRedirectAcceptor(ln net.Listener, name string) (*RedirectAcceptor, error) {
	return &RedirectAcceptor{ln: ln, name: name}, nil
}

func (a *RedirectAcceptor) Accept() (Session, error) {
	conn, err := a.ln.Accept()
	if err != nil {
		return Session{}, err
	}

	dst, err := originalDst(conn)
	if err != nil {
		conn.Close()
		return Session{}, fmt.Errorf("redirect: recover original destination: %w", err)
	}

	var client netip.AddrPort
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		client = tcpAddrPort(tcpAddr)
	}

	return Session{Client: client, Dst: dst, Transport: TransportRedirect, Conn: conn, Acceptor: a.name}, nil
}

func (a *RedirectAcceptor) Close() error {
	return a.ln.Close()
}

// ip6tSoOriginalDst is IP6T_SO_ORIGINAL_DST — the IPv6 NAT counterpart to
// unix.SO_ORIGINAL_DST. The Linux kernel deliberately reuses the same
// numeric value (80) for both (net/netfilter/nf_conntrack_l3proto_*.c),
// so this isn't a distinct constant so much as unix.SO_ORIGINAL_DST used
// at SOL_IPV6 instead of SOL_IP; x/sys/unix has no separate named
// constant for it, so it's spelled out explicitly here rather than
// silently reusing unix.SO_ORIGINAL_DST at the wrong level and hoping a
// reader notices.
const ip6tSoOriginalDst = unix.SO_ORIGINAL_DST

// originalDst recovers a REDIRECT-accepted connection's pre-NAT
// destination via SO_ORIGINAL_DST, the only way to learn it — the
// accepted connection's own LocalAddr() is the listener's own address
// (where DNAT actually delivered the packet), not the client's real
// target.
func originalDst(conn net.Conn) (netip.AddrPort, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("not a TCP connection (%T)", conn)
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("SyscallConn: %w", err)
	}

	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("LocalAddr: not a TCP address (%T)", conn.LocalAddr())
	}
	is4 := localAddr.IP.To4() != nil

	var dst netip.AddrPort
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		if is4 {
			dst, sockErr = getOriginalDst4(fd)
		} else {
			dst, sockErr = getOriginalDst6(fd)
		}
	})
	if ctrlErr != nil {
		return netip.AddrPort{}, fmt.Errorf("Control: %w", ctrlErr)
	}
	if sockErr != nil {
		return netip.AddrPort{}, sockErr
	}
	return dst, nil
}

// ntohs converts a network-byte-order port (as stored in a raw
// sockaddr's Port field) to a host-byte-order uint16.
func ntohs(p uint16) uint16 { return p>>8 | p<<8 }

// getOriginalDst4/6 issue the raw SYS_GETSOCKOPT syscall directly: x/sys/
// unix exposes the SO_ORIGINAL_DST/SOL_IP*/RawSockaddrInet* constants and
// types this needs, but no typed wrapper function for this specific
// option (it's Linux-netfilter-specific, not a general sockopt). The
// unsafe.Pointer->uintptr conversions happen inline in the Syscall6 call
// itself, the documented-safe pattern for a raw syscall trampoline
// implemented in assembly (see the unsafe package doc's "syscall.Syscall"
// exception) — do not hoist raw/size into intermediately-converted
// uintptr variables, that pattern is unsafe.
func getOriginalDst4(fd uintptr) (netip.AddrPort, error) {
	var raw unix.RawSockaddrInet4
	size := uint32(unix.SizeofSockaddrInet4)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return netip.AddrPort{}, fmt.Errorf("getsockopt SOL_IP/SO_ORIGINAL_DST: %w", errno)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(raw.Addr), ntohs(raw.Port)), nil
}

func getOriginalDst6(fd uintptr) (netip.AddrPort, error) {
	var raw unix.RawSockaddrInet6
	size := uint32(unix.SizeofSockaddrInet6)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, uintptr(unix.SOL_IPV6), uintptr(ip6tSoOriginalDst),
		uintptr(unsafe.Pointer(&raw)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return netip.AddrPort{}, fmt.Errorf("getsockopt SOL_IPV6/IP6T_SO_ORIGINAL_DST: %w", errno)
	}
	return netip.AddrPortFrom(netip.AddrFrom16(raw.Addr), ntohs(raw.Port)), nil
}

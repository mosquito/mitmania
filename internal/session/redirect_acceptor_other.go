//go:build !linux

package session

import (
	"fmt"
	"net"
	"runtime"
)

// RedirectAcceptor exists on every platform so cross-compiled builds keep
// working (CLAUDE.md requires the full release GOOS matrix to keep
// building), but REDIRECT destination recovery (SO_ORIGINAL_DST) is a
// Linux netfilter feature with no equivalent elsewhere — this build
// simply cannot serve it.
type RedirectAcceptor struct{}

// NewRedirectAcceptor always fails on non-Linux platforms — there is no
// portable way to recover a REDIRECT-DNAT connection's original
// destination.
func NewRedirectAcceptor(ln net.Listener, name string) (*RedirectAcceptor, error) {
	return nil, fmt.Errorf("redirect: not supported on GOOS=%s (Linux-only)", runtime.GOOS)
}

func (a *RedirectAcceptor) Accept() (Session, error) {
	return Session{}, fmt.Errorf("redirect: not supported on GOOS=%s (Linux-only)", runtime.GOOS)
}

func (a *RedirectAcceptor) Close() error { return nil }

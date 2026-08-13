package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

var errHeadersTooLarge = errors.New("proxy: request headers too large")

// errEmptyConnection wraps boundNextHeaderBlock's error when the
// connection ended (EOF or otherwise) before a single byte was received —
// a speculative/aborted TCP connection with no request at all, not a
// malformed one. Both explicit clients (health checks, connection racing)
// and transparently-intercepted ones hit this constantly and harmlessly;
// callers use it to log a distinct, quieter outcome than "invalid-request"
// rather than conflating "sent nothing" with "sent garbage."
var errEmptyConnection = errors.New("proxy: connection closed before any bytes were received")

// prependConn keeps replay bytes on the connection itself, rather than in
// a temporary bufio.Reader wrapper. That matters when an HTTP Upgrade
// hands the connection to relay(): bytes prefetched behind the 101/request
// headers must remain visible even after HTTP parsing stops.
type prependConn struct {
	net.Conn
	r io.Reader
}

func newPrependConn(conn net.Conn) *prependConn {
	return &prependConn{Conn: conn, r: conn}
}

func (c *prependConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *prependConn) prepend(p []byte) {
	if len(p) > 0 {
		c.r = io.MultiReader(bytes.NewReader(p), c.r)
	}
}

// CloseWrite half-closes the write side, if the underlying connection
// supports it. Embedding net.Conn (an interface) does not promote this on
// its own: Go only promotes methods the embedded field's declared TYPE
// has, not ones the concrete value stored in it happens to implement —
// net.Conn doesn't declare CloseWrite, so without this, relay's
// halfCloser check silently no-ops for a prependConn tunnel even when the
// real connection underneath (almost always a *net.TCPConn) supports it.
// That would leave the still-open direction never signaled, only ever
// resolved by the whole connection eventually closing outright — bad for
// any protocol that relies on a clean half-close, not just an eventual
// hard close.
func (c *prependConn) CloseWrite() error {
	if cw, ok := c.Conn.(halfCloser); ok {
		return cw.CloseWrite()
	}
	return nil
}

// normalizeAuthority turns an HTTP authority into the exact dial address
// and the host/port pair used by policy. Ports are deliberately numeric:
// accepting local service-name resolution here would make the destination
// depend on the proxy host's /etc/services rather than the request.
func normalizeAuthority(authority, defaultPort string) (host, port, dst string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", "", errors.New("empty authority")
	}

	host, port, err = net.SplitHostPort(authority)
	if err != nil {
		port = defaultPort
		host = authority
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		} else if strings.Contains(host, ":") {
			if _, ipErr := netip.ParseAddr(host); ipErr != nil {
				return "", "", "", fmt.Errorf("invalid authority %q: %w", authority, err)
			}
		}
	}
	if host == "" {
		return "", "", "", fmt.Errorf("invalid authority %q: empty host", authority)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", "", fmt.Errorf("invalid authority %q: bad port %q", authority, port)
	}
	policyHost, err := canonicalHost(host)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid authority %q: %w", authority, err)
	}
	return policyHost, port, net.JoinHostPort(host, port), nil
}

func canonicalHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("invalid host %q", host)
	}
	return strings.ToLower(ascii), nil
}

func sameHost(a, b string) bool {
	ca, errA := canonicalHost(a)
	cb, errB := canonicalHost(b)
	return errA == nil && errB == nil && ca == cb
}

// authorityMatches binds every request on a persistent connection to the
// origin authorized for that connection. This is the h1/h2 equivalent of
// preventing origin coalescing from turning one allowed socket into access
// to another virtual host.
func authorityMatches(got, expectHost, expectPort, proto string) bool {
	defaultPort := "80"
	if proto == "https" {
		defaultPort = "443"
	}
	host, port, _, err := normalizeAuthority(got, defaultPort)
	return err == nil && sameHost(host, expectHost) && port == expectPort
}

// boundNextHeaderBlock scans exactly through the next blank line before
// handing the bytes back to net/http's parser. Unlike io.LimitedReader
// around the whole connection, this bounds every keep-alive request without
// also truncating its body. Bytes bufio prefetched after the header are
// replayed before reads resume from conn — on EOF/reset failure too, not
// just success: a caller that just closes on error is unaffected, but the
// transparent-HTTP path falls back to raw opaque-TCP passthrough when a
// connection turns out not to be HTTP at all, and that needs every byte
// the client actually sent, not just the success-path subset. (A
// too-large, terminator-less block is the one exception — that shape is a
// probe/memory-exhaustion attempt, not a legitimate opaque protocol's
// short handshake, so nothing is replayed for it.)
func boundNextHeaderBlock(br *bufio.Reader, conn *prependConn, limit int) error {
	if limit <= 0 {
		return errHeadersTooLarge
	}
	var header bytes.Buffer
	var loopErr error
	for {
		fragment, err := br.ReadSlice('\n')
		if header.Len()+len(fragment) > limit {
			return errHeadersTooLarge
		}
		header.Write(fragment)
		data := header.Bytes()
		if bytes.HasSuffix(data, []byte("\r\n\r\n")) || bytes.HasSuffix(data, []byte("\n\n")) {
			break
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			loopErr = err
			break
		}
	}

	prefetched := make([]byte, br.Buffered())
	if len(prefetched) > 0 {
		if _, err := io.ReadFull(br, prefetched); err != nil && loopErr == nil {
			loopErr = err
		}
	}
	replay := make([]byte, 0, header.Len()+len(prefetched))
	replay = append(replay, header.Bytes()...)
	replay = append(replay, prefetched...)
	if len(replay) > 0 {
		conn.prepend(replay)
		br.Reset(conn)
	}

	if loopErr != nil {
		if header.Len() == 0 {
			return fmt.Errorf("%w: %w", errEmptyConnection, loopErr)
		}
		return loopErr
	}
	return nil
}

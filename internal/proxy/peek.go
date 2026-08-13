// Package proxy implements mitmania's transport-agnostic request pipeline:
// the dispatcher/selector, the HTTP/1.1 and raw-splice handlers, and the
// on-demand TLS termination service that drives certificate cloning.
package proxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
)

// PeekedHello is what a ClientHello peek discovered without completing (or
// meaningfully starting) a TLS handshake.
type PeekedHello struct {
	ServerName string
	ALPN       []string
	Raw        []byte // exact bytes read from the wire while peeking
}

var errPeekAbort = errors.New("proxy: peek: aborting handshake after ClientHello capture")

// PeekClientHello reads just enough of conn to parse the ClientHello (SNI,
// ALPN) by reusing crypto/tls's own parser, then aborts before any
// certificate is chosen or any byte is sent back to the client.
//
// It does this by running a throwaway tls.Server handshake over a
// recordingConn that tees every Read into a buffer and discards every
// Write. GetConfigForClient captures SNI/ALPN from the
// *tls.ClientHelloInfo crypto/tls already parsed, then returns an error to
// abort — crypto/tls's server handshake responds to that error by sending
// an alert (see handshake_server.go's c.sendAlert(alertInternalError)),
// which lands on our no-op Write and never reaches the real network
// connection. The recorded bytes are returned in Raw so the caller can
// replay them (via Replay) into whatever handshake comes next.
func PeekClientHello(conn net.Conn) (*PeekedHello, error) {
	rec := &recordingConn{Conn: conn}
	hello := &PeekedHello{}

	cfg := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello.ServerName = info.ServerName
			hello.ALPN = append([]string(nil), info.SupportedProtos...)
			return nil, errPeekAbort
		},
	}

	err := tls.Server(rec, cfg).Handshake()
	hello.Raw = rec.buf.Bytes()

	switch {
	case errors.Is(err, errPeekAbort):
		return hello, nil
	case err == nil:
		// Should be unreachable: GetConfigForClient always returns an
		// error, so the handshake can never actually succeed.
		return hello, errors.New("proxy: peek: handshake unexpectedly succeeded")
	default:
		// GetConfigForClient was never reached — e.g. the client isn't
		// speaking TLS at all, or sent a malformed/truncated ClientHello.
		// Return what was recorded (possibly empty) alongside the error so
		// the caller can decide (typically: not TLS, splice raw as-is).
		return hello, err
	}
}

// recordingConn tees Read into buf and discards Write, so a throwaway
// handshake driven over it can observe the client's bytes without ever
// writing anything back to the real network connection.
type recordingConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) {
	return len(p), nil
}

// Replay wraps conn so the first bytes read back out are prefix, then
// falls through to conn — used after PeekClientHello so neither a real
// handshake nor a mitm:false raw splice ever needs the client to resend
// its ClientHello. Writes pass straight through to conn.
func Replay(conn net.Conn, prefix []byte) net.Conn {
	return &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// CloseWrite half-closes the write side, if the underlying connection
// supports it — see prependConn.CloseWrite for why this can't just be
// promoted from the embedded net.Conn. Every transparent-mode mitm:false
// splice goes through Replay (peeking is unconditional there, unlike
// explicit CONNECT), so without this, relay's halfCloser optimization
// would silently no-op for all of it.
func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(halfCloser); ok {
		return cw.CloseWrite()
	}
	return nil
}

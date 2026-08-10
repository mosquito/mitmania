package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"mitmania/internal/httperror"
	"mitmania/internal/telemetry"
)

// CertFactory is the subset of *cert.CertFactory TLSService needs — kept
// as an interface here so this package doesn't import internal/cert (the
// dependency runs the other way: cmd/mitmania wires a *cert.CertFactory in).
type CertFactory interface {
	For(ctx context.Context, sni string, realChain []*x509.Certificate) (*tls.Certificate, error)
	// Fallback mints a synthetic leaf for sni alone, with no real chain to
	// clone — used by TLSService.Fallback for the "Over-TLS" error-delivery path.
	Fallback(ctx context.Context, sni string) (*tls.Certificate, error)
}

// TLSService performs on-demand TLS termination — an on-demand service,
// not a fixed pipeline stage, so STARTTLS-style mid-stream handlers can
// call it too. For v1's HTTP/1.1-only path it is
// called exactly once per intercepted connection, after the connection-phase
// rule decision.
type TLSService struct {
	Factory CertFactory

	// Metrics backs the tls.handshake.duration (leg=client) metric — nil-safe,
	// same convention as everywhere else. The upstream leg is recorded by
	// UpstreamDialer itself (DialTLS), not here.
	Metrics *telemetry.Metrics
}

// TerminateResult bundles the client-facing handshake and the already-open
// upstream connection so the caller (Http1Handler) doesn't need to dial
// upstream a second time to relay the actual request — the certificate
// fetch already paid that cost ("MITM dials upstream on every
// connection"). This is a deliberate extension of the entity-model
// diagram, which shows Terminate returning just (net.Conn, alpn).
type TerminateResult struct {
	Client       *tls.Conn
	Upstream     *tls.Conn
	ALPN         string // negotiated with the client
	UpstreamALPN string // negotiated with the real origin
}

// terminatePhase identifies which step of Terminate failed, so a caller
// can decide whether a fallback handshake (the "Over-TLS" error-delivery
// path) is still safe to attempt: a dial or mint failure happens before the
// client's real handshake ever starts (clientConn is still pristine), but
// once HandshakeContext has been attempted, the client's TLS record-layer
// state may already be desynced — nothing further should be attempted on
// that connection.
type terminatePhase string

const (
	PhaseDial      terminatePhase = "dial"      // upstream TCP+TLS dial/handshake
	PhaseMint      terminatePhase = "mint"      // our own cert cloning
	PhaseHandshake terminatePhase = "handshake" // client-facing handshake
)

// TerminateError wraps a Terminate failure with the phase it occurred in.
type TerminateError struct {
	Phase terminatePhase
	err   error
}

func (e *TerminateError) Error() string { return e.err.Error() }
func (e *TerminateError) Unwrap() error { return e.err }

// Terminate dials dst over TLS (using sni as both the TLS ServerName and
// the identity CertFactory clones), then completes a TLS handshake with
// the client over clientConn using the synthetic certificate. clientConn
// should already have been wrapped with Replay of any bytes consumed by an
// earlier PeekClientHello, so the client never has to resend its
// ClientHello.
func (s *TLSService) Terminate(ctx context.Context, clientConn net.Conn, dialer UpstreamDialer, dst, sni string) (*TerminateResult, error) {
	upstream, err := dialer.DialTLS(ctx, "tcp", dst, sni)
	if err != nil {
		return nil, &TerminateError{Phase: PhaseDial, err: fmt.Errorf("proxy: tlsservice: dial upstream %s: %w", dst, err)}
	}

	realChain := upstream.ConnectionState().PeerCertificates
	tlsCert, err := s.Factory.For(ctx, sni, realChain)
	if err != nil {
		upstream.Close()
		return nil, &TerminateError{Phase: PhaseMint, err: fmt.Errorf("proxy: tlsservice: clone cert for %s: %w", sni, err)}
	}

	upstreamALPN := upstream.ConnectionState().NegotiatedProtocol

	// Client offer mirrors what upstream actually negotiated: h2 is only
	// ever offered to the client when the one upstream connection we
	// dialed for this session also speaks h2, since we don't multiplex an
	// h2 client onto a non-multiplexing h1 upstream. When upstream is h1,
	// downgrade to http/1.1-only, same as before.
	clientProtos := []string{"http/1.1"}
	if upstreamALPN == "h2" {
		clientProtos = []string{"h2", "http/1.1"}
	}

	clientTLS := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   clientProtos,
	})
	hsStart := time.Now()
	hsErr := clientTLS.HandshakeContext(ctx)
	hsResult := "ok"
	if hsErr != nil {
		hsResult = "tls"
	}
	s.Metrics.TLSHandshake(ctx, "client", hsResult, time.Since(hsStart))
	if hsErr != nil {
		upstream.Close()
		return nil, &TerminateError{Phase: PhaseHandshake, err: fmt.Errorf("proxy: tlsservice: client handshake for %s: %w", sni, hsErr)}
	}

	return &TerminateResult{
		Client:       clientTLS,
		Upstream:     upstream,
		ALPN:         clientTLS.ConnectionState().NegotiatedProtocol,
		UpstreamALPN: upstreamALPN,
	}, nil
}

// Fallback completes a TLS handshake with the client using a synthetic
// leaf minted for sni alone (the "Over-TLS" error-delivery path: there's
// no real chain to clone — this is exactly for when Terminate couldn't get one),
// then serves spec's Squid-style error page over that session — so a
// post-CONNECT upstream failure still reaches the client as a page instead
// of a bare TLS reset. Only call this when clientConn hasn't already had a
// real handshake attempted on it (a PhaseDial or PhaseMint TerminateError,
// never PhaseHandshake).
func (s *TLSService) Fallback(ctx context.Context, clientConn net.Conn, sni, reqURL string, spec httperror.Spec) error {
	tlsCert, err := s.Factory.Fallback(ctx, sni)
	if err != nil {
		return fmt.Errorf("proxy: tlsservice: fallback cert for %s: %w", sni, err)
	}
	clientTLS := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"http/1.1"},
	})
	hsStart := time.Now()
	hsErr := clientTLS.HandshakeContext(ctx)
	hsResult := "ok"
	if hsErr != nil {
		hsResult = "tls"
	}
	s.Metrics.TLSHandshake(ctx, "client", hsResult, time.Since(hsStart))
	if hsErr != nil {
		return fmt.Errorf("proxy: tlsservice: fallback handshake for %s: %w", sni, hsErr)
	}
	defer clientTLS.Close()
	return httperror.WriteResponse(clientTLS, reqURL, spec)
}

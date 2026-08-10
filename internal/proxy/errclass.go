package proxy

import (
	"errors"
	"io"
	"net"

	"mitmania/internal/httperror"
)

// classifyConnectErr maps a failure from establishing the upstream
// connection (TCP dial, or the TLS handshake on top of it) to the
// Cloudflare-style 52x taxonomy: DNS failure, refused/down, or a
// connect-phase timeout.
func classifyConnectErr(err error) httperror.Spec {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return httperror.UpstreamUnreachable
	}
	if isTimeout(err) {
		return httperror.ConnectTimeout
	}
	return httperror.UpstreamDown
}

// classifyReadErr maps a failure from an already-established upstream
// connection (waiting for/reading a response) to the same Cloudflare-style
// 52x taxonomy: read-phase timeout, upstream closed without sending anything, or
// anything else unparseable as a response.
func classifyReadErr(err error) httperror.Spec {
	if isTimeout(err) {
		return httperror.ReadTimeout
	}
	if errors.Is(err, io.EOF) {
		return httperror.ZeroSizeObject
	}
	return httperror.BadGateway
}

// classifyTerminateDialErr classifies a TLSService.Terminate PhaseDial
// failure. Unlike classifyConnectErr, this is reached only after
// serveConnect's own plain-TCP probe already confirmed basic reachability
// moments earlier — so an unclassified failure here defaults to a TLS
// handshake failure (525) rather than refused/down (521), since plain
// connectivity was already ruled out and DialTLS's own handshake is the
// only new thing this dial attempt adds.
func classifyTerminateDialErr(err error) httperror.Spec {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return httperror.UpstreamUnreachable
	}
	if isTimeout(err) {
		return httperror.ConnectTimeout
	}
	return httperror.TLSHandshakeFail
}

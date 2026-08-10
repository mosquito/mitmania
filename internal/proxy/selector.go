package proxy

import (
	"context"

	"mitmania/internal/session"
)

// ProtocolHandler is the extension seam: it owns the decision of
// whether/when to call TLSService. Http1Handler is the only implementation
// this pass; SshHandler/ImapHandler/Http2Handler/Http3Handler are the
// documented extensibility points for adding new protocols.
type ProtocolHandler interface {
	Serve(ctx context.Context, sess session.Session, dialer UpstreamDialer)
}

// Selector picks which ProtocolHandler serves a Session. The entity model
// specs Pick(port,alpn,firstBytes) for protocol demux ahead of any handler
// running — that data doesn't exist yet in v1 (nothing sniffs before
// Http1Handler itself peeks), so this pass's Selector is a single default;
// per-port/ALPN/sniffed routing is the seam SSH/IMAP/h2/h3 add later.
type Selector struct {
	Default ProtocolHandler
}

func (s *Selector) Pick(sess session.Session) ProtocolHandler {
	return s.Default
}

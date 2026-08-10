package proxy

import (
	"context"
	"fmt"
	"net"
)

// rawSplice implements mitm:false: relay tunnel <-> a freshly
// dialed plain TCP connection to dst, with no TLS termination and no rule
// application beyond the connection-phase decision that already selected
// this path. Whatever TLS the client negotiates with dst from here is
// never touched — the real certificate passes through untouched.
func rawSplice(ctx context.Context, tunnel net.Conn, dialer UpstreamDialer, dst string) error {
	upstream, err := dialer.Dial(ctx, "tcp", dst)
	if err != nil {
		return fmt.Errorf("proxy: rawsplice: dial %s: %w", dst, err)
	}
	defer upstream.Close()

	relay(tunnel, upstream)
	return nil
}

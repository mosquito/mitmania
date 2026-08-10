package proxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"mitmania/internal/rules"
)

// resolver is the subset of UpstreamDialer resolveAndPin needs — kept as
// its own tiny interface (rather than taking the full UpstreamDialer) so
// its signature stays obviously about resolution, not dialing.
type resolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// egressDeniedError reports that the egress[] destination-address policy
// refused a resolved destination address — distinct from a DNS/lookup
// failure so callers can deliver httperror.ForwardingDenied instead of a
// generic connect-fail classification.
type egressDeniedError struct {
	addr netip.Addr
}

func (e *egressDeniedError) Error() string {
	return fmt.Sprintf("proxy: egress policy denies %s", e.addr)
}

// resolveAndPin implements the egress-policy resolve-phase — inserted
// between the connection-phase rule firstmatch and the upstream dial, on
// both the mitm
// and mitm:false paths. host is resolved exactly once; every returned
// address is evaluated against ruleSet's egress[] list, and only if every
// one is allowed does this return a dial target with host replaced by one
// pinned literal address. Callers must use the returned string (not host)
// for every subsequent dial tied to this connection, so nothing
// downstream re-resolves the name — a second lookup could legitimately
// answer differently from the one actually checked (DNS rebinding).
//
// host already being a literal IP (a transparent-mode dst, or a client
// CONNECTing straight to an address) skips the lookup: there's only the
// one address to check, and no name to rebind.
func resolveAndPin(ctx context.Context, ruleSet *rules.RuleSet, res resolver, host, port, proto string) (pinnedDst string, err error) {
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("proxy: invalid port %q: %w", port, err)
	}

	var addrs []netip.Addr
	if addr, aerr := netip.ParseAddr(host); aerr == nil {
		addrs = []netip.Addr{addr}
	} else {
		addrs, err = res.LookupIP(ctx, host)
		if err != nil {
			return "", err
		}
	}

	// Every returned address must be allowed, not just the one that ends
	// up dialed — a name answering with both a public and a loopback
	// address is not one we want to serve either half of.
	for _, addr := range addrs {
		if allow, _ := ruleSet.LookupEgress(addr, uint16(portNum), proto); !allow {
			return "", &egressDeniedError{addr: addr}
		}
	}

	return net.JoinHostPort(addrs[0].String(), port), nil
}

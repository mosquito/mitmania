package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses --trusted-proxies' "<cidr[,cidr…]>" value:
// a comma-separated list of CIDR prefixes, or bare IPs (treated
// as a single-address /32 or /128 prefix — the common case of naming one
// fronting LB/proxy shouldn't require spelling out "/32"). Empty s
// returns a nil slice — client-IP recovery from XFF/X-Real-IP disabled,
// the default.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	if s == "" {
		return nil, nil
	}
	var prefixes []netip.Prefix
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid --trusted-proxies %q: empty entry", s)
		}
		if prefix, err := netip.ParsePrefix(part); err == nil {
			prefixes = append(prefixes, prefix)
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid --trusted-proxies entry %q: not a CIDR or IP", part)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

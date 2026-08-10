package config

import (
	"fmt"
	"net/url"
	"strconv"
)

// defaultHTTPSProxyName is --listen-https-proxy's ?cn= default when no
// ?cn= is given at all: the sole entry of Names, becoming both the
// Subject.CommonName and (as a DNSNames SAN) the identity a client
// verifies against. Deliberately generic, matching the root CA's own
// non-descriptive Subject — an operator wanting real hostname
// verification passes ?cn= with a syntactically valid hostname/IP
// (repeatable: ?cn=Friendly%20Name&cn=proxy.internal.example pairs a
// free-text CN with one or more additional, verifiable SAN entries).
const defaultHTTPSProxyName = "Internal Proxy"

// defaultHTTPSProxyPort is filled in when --listen-https-proxy's URL
// omits a port — https conventionally means 443.
const defaultHTTPSProxyPort = 443

// HTTPSProxyAddr is a parsed --listen-https-proxy value: the listener
// address (tcp only — a TLS-terminating, internet-facing endpoint has no
// sensible unix-socket form) plus Names, the ordered list from one or
// more repeated ?cn= query params identifying its own certificate
// (Names[0] -> Subject.CommonName, the full list -> SAN set).
type HTTPSProxyAddr struct {
	Addr  Addr
	Names []string
}

// ParseHTTPSProxyAddr parses "tcp://HOST[:PORT][/?cn=...[&cn=...]]" —
// port defaults to 443 when omitted; Names defaults to
// [defaultHTTPSProxyName] when no ?cn= is given. Opt-in like every other
// listener: this is only ever called when --listen-https-proxy was
// actually given.
func ParseHTTPSProxyAddr(s string) (HTTPSProxyAddr, error) {
	u, err := url.Parse(s)
	if err != nil {
		return HTTPSProxyAddr{}, fmt.Errorf("invalid address %q: %w", s, err)
	}
	if u.Scheme != "tcp" {
		return HTTPSProxyAddr{}, fmt.Errorf("invalid address %q: unsupported scheme %q (need tcp://)", s, u.Scheme)
	}

	host := u.Hostname()
	if host == "*" {
		host = ""
	}

	port := defaultHTTPSProxyPort
	if portStr := u.Port(); portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 0 || port > 65535 {
			return HTTPSProxyAddr{}, fmt.Errorf("invalid address %q: bad port %q", s, portStr)
		}
	}

	var names []string
	for _, n := range u.Query()["cn"] {
		if n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		names = []string{defaultHTTPSProxyName}
	}

	return HTTPSProxyAddr{Addr: Addr{Scheme: "tcp", Host: host, Port: port}, Names: names}, nil
}

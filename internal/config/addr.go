// Package config parses mitmania's CLI flags and validates listener addresses.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// Addr is a parsed --listen-*/--control value, e.g. "tcp://*:3128" or
// "unix:///var/run/mitmania.sock".
type Addr struct {
	Scheme string // "tcp", "udp", or "unix"
	Host   string // "" means all interfaces (v4+v6); set from "*"
	Port   int    // tcp/udp only
	Path   string // unix only
}

// ParseAddr parses a URL-like listener address: "tcp://HOST:PORT",
// "udp://HOST:PORT", or "unix:///path". "*" as the host means all
// interfaces.
func ParseAddr(s string) (Addr, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Addr{}, fmt.Errorf("invalid address %q: %w", s, err)
	}

	switch u.Scheme {
	case "tcp", "udp":
		host := u.Hostname()
		if host == "*" {
			host = ""
		}
		portStr := u.Port()
		if portStr == "" {
			return Addr{}, fmt.Errorf("invalid address %q: missing port", s)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 0 || port > 65535 {
			return Addr{}, fmt.Errorf("invalid address %q: bad port %q", s, portStr)
		}
		return Addr{Scheme: u.Scheme, Host: host, Port: port}, nil
	case "unix":
		// url.Parse splits "unix://./.mitmania.sock" into Host="." Path="/.mitmania.sock";
		// concatenating them recovers the relative path "./.mitmania.sock" the caller
		// wrote, while "unix:///abs/path" (empty Host) is left as the absolute path.
		path := u.Host + u.Path
		if path == "" {
			return Addr{}, fmt.Errorf("invalid address %q: missing path", s)
		}
		return Addr{Scheme: u.Scheme, Path: path}, nil
	case "":
		return Addr{}, fmt.Errorf("invalid address %q: missing scheme (expected tcp://, udp://, or unix://)", s)
	default:
		return Addr{}, fmt.Errorf("invalid address %q: unsupported scheme %q", s, u.Scheme)
	}
}

// Network returns the value suitable for net.Listen's network argument.
func (a Addr) Network() string {
	return a.Scheme
}

// String returns the value suitable for net.Listen's address argument.
func (a Addr) String() string {
	if a.Scheme == "unix" {
		return a.Path
	}
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

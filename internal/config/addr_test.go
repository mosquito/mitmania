package config

import (
	"net"
	"testing"
)

func TestParseAddr(t *testing.T) {
	tests := []struct {
		in      string
		want    Addr
		wantErr bool
	}{
		{in: "tcp://*:3128", want: Addr{Scheme: "tcp", Host: "", Port: 3128}},
		{in: "tcp://127.0.0.1:3128", want: Addr{Scheme: "tcp", Host: "127.0.0.1", Port: 3128}},
		{in: "udp://*:3132", want: Addr{Scheme: "udp", Host: "", Port: 3132}},
		{in: "unix:///var/run/mitmania.sock", want: Addr{Scheme: "unix", Path: "/var/run/mitmania.sock"}},
		{in: "unix:///.mitmania.sock", want: Addr{Scheme: "unix", Path: "/.mitmania.sock"}},
		{in: "unix://./.mitmania.sock", want: Addr{Scheme: "unix", Path: "./.mitmania.sock"}},
		{in: "tcp://[::1]:3128", want: Addr{Scheme: "tcp", Host: "::1", Port: 3128}},
		{in: "tcp://[2001:db8::1]:8443", want: Addr{Scheme: "tcp", Host: "2001:db8::1", Port: 8443}},
		{in: "udp://[::]:3132", want: Addr{Scheme: "udp", Host: "::", Port: 3132}},
		{in: "tcp://*", wantErr: true},
		{in: "bogus://x", wantErr: true},
		{in: "not a url either", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseAddr(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseAddr(%q): expected error, got %+v", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAddr(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseAddr(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestAddrString(t *testing.T) {
	a := Addr{Scheme: "tcp", Host: "", Port: 3128}
	if got, want := a.String(), ":3128"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	u := Addr{Scheme: "unix", Path: "/tmp/x.sock"}
	if got, want := u.String(), "/tmp/x.sock"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	v6 := Addr{Scheme: "tcp", Host: "::1", Port: 3128}
	if got, want := v6.String(), "[::1]:3128"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestParseAddrIPv6RoundTrip guards the bracket-stripping/re-adding dance
// url.Parse and net.JoinHostPort each do for IPv6 literals.
func TestParseAddrIPv6RoundTrip(t *testing.T) {
	for _, in := range []string{"tcp://[::1]:3128", "tcp://[2001:db8::1]:8443", "udp://[fe80::1%25eth0]:53"} {
		a, err := ParseAddr(in)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", in, err)
		}
		if _, _, err := net.SplitHostPort(a.String()); err != nil {
			t.Errorf("ParseAddr(%q).String() = %q not a valid host:port: %v", in, a.String(), err)
		}
	}
}

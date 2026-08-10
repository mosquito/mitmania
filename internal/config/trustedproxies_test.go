package config

import (
	"net/netip"
	"testing"
)

func TestParseTrustedProxies_Empty(t *testing.T) {
	got, err := ParseTrustedProxies("")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if got != nil {
		t.Fatalf("got %v, want nil (recovery disabled)", got)
	}
}

func TestParseTrustedProxies_SingleCIDR(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTrustedProxies_BareIPv4BecomesSlash32(t *testing.T) {
	got, err := ParseTrustedProxies("192.0.2.1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	want := netip.MustParsePrefix("192.0.2.1/32")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want [%v]", got, want)
	}
}

func TestParseTrustedProxies_BareIPv6BecomesSlash128(t *testing.T) {
	got, err := ParseTrustedProxies("2001:db8::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	want := netip.MustParsePrefix("2001:db8::1/128")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want [%v]", got, want)
	}
}

func TestParseTrustedProxies_IPv6CIDR(t *testing.T) {
	got, err := ParseTrustedProxies("2001:db8::/32")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	want := netip.MustParsePrefix("2001:db8::/32")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want [%v]", got, want)
	}
}

func TestParseTrustedProxies_MixedV4AndV6List(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8,2001:db8::/32,192.0.2.1,::1")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("192.0.2.1/32"),
		netip.MustParsePrefix("::1/128"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseTrustedProxies_TrimsWhitespace(t *testing.T) {
	got, err := ParseTrustedProxies(" 10.0.0.0/8 , 2001:db8::/32 ")
	if err != nil {
		t.Fatalf("ParseTrustedProxies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 entries", got)
	}
}

func TestParseTrustedProxies_RejectsGarbage(t *testing.T) {
	if _, err := ParseTrustedProxies("not-an-address"); err == nil {
		t.Fatalf("expected an error for a non-address entry")
	}
}

func TestParseTrustedProxies_RejectsEmptyEntry(t *testing.T) {
	if _, err := ParseTrustedProxies("10.0.0.0/8,,192.0.2.1"); err == nil {
		t.Fatalf("expected an error for an empty entry between commas")
	}
}

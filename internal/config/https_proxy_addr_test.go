package config

import (
	"reflect"
	"testing"
)

func TestParseHTTPSProxyAddr_PortDefaultsTo443(t *testing.T) {
	got, err := ParseHTTPSProxyAddr("tcp://*")
	if err != nil {
		t.Fatalf("ParseHTTPSProxyAddr: %v", err)
	}
	if got.Addr.Port != 443 {
		t.Fatalf("Port = %d, want 443 default", got.Addr.Port)
	}
	if got.Addr.Host != "" {
		t.Fatalf("Host = %q, want \"\" (wildcard)", got.Addr.Host)
	}
}

func TestParseHTTPSProxyAddr_ExplicitPortOverridesDefault(t *testing.T) {
	got, err := ParseHTTPSProxyAddr("tcp://*:8443")
	if err != nil {
		t.Fatalf("ParseHTTPSProxyAddr: %v", err)
	}
	if got.Addr.Port != 8443 {
		t.Fatalf("Port = %d, want 8443", got.Addr.Port)
	}
}

func TestParseHTTPSProxyAddr_NamesDefaultsToInternalProxy(t *testing.T) {
	got, err := ParseHTTPSProxyAddr("tcp://*:443")
	if err != nil {
		t.Fatalf("ParseHTTPSProxyAddr: %v", err)
	}
	if want := []string{"Internal Proxy"}; !reflect.DeepEqual(got.Names, want) {
		t.Fatalf("Names = %v, want %v", got.Names, want)
	}
}

func TestParseHTTPSProxyAddr_ExplicitSingleCN(t *testing.T) {
	got, err := ParseHTTPSProxyAddr("tcp://*:443/?cn=proxy.internal.example")
	if err != nil {
		t.Fatalf("ParseHTTPSProxyAddr: %v", err)
	}
	if want := []string{"proxy.internal.example"}; !reflect.DeepEqual(got.Names, want) {
		t.Fatalf("Names = %v, want %v", got.Names, want)
	}
}

func TestParseHTTPSProxyAddr_RepeatedCNPreservesOrder(t *testing.T) {
	got, err := ParseHTTPSProxyAddr("tcp://*:443/?cn=Friendly%20Name&cn=proxy.internal.example&cn=10.0.0.5")
	if err != nil {
		t.Fatalf("ParseHTTPSProxyAddr: %v", err)
	}
	want := []string{"Friendly Name", "proxy.internal.example", "10.0.0.5"}
	if !reflect.DeepEqual(got.Names, want) {
		t.Fatalf("Names = %v, want %v", got.Names, want)
	}
}

func TestParseHTTPSProxyAddr_RejectsNonTCPScheme(t *testing.T) {
	if _, err := ParseHTTPSProxyAddr("unix:///run/mitmania-https.sock"); err == nil {
		t.Fatalf("expected an error for unix:// scheme, got nil")
	}
}

func TestParseHTTPSProxyAddr_RejectsBadPort(t *testing.T) {
	if _, err := ParseHTTPSProxyAddr("tcp://*:notaport"); err == nil {
		t.Fatalf("expected an error for a non-numeric port, got nil")
	}
}

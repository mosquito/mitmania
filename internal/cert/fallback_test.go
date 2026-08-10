package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
)

func TestCertFactory_Fallback_ValidatesAgainstOurRoot(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	const sni = "unreachable.example.com"
	tlsCert, err := factory.Fallback(context.Background(), sni)
	if err != nil {
		t.Fatalf("Fallback: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if leaf.Subject.CommonName != sni {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, sni)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != sni {
		t.Errorf("DNSNames = %v, want [%s]", leaf.DNSNames, sni)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: roots}); err != nil {
		t.Fatalf("fallback leaf does not validate against our root: %v", err)
	}

	wantKey, err := (DetKeyDeriver{ClusterKey: ck}).LeafKey([]string{"dns:" + sni})
	if err != nil {
		t.Fatal(err)
	}
	gotKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("PrivateKey is %T, want *ecdsa.PrivateKey", tlsCert.PrivateKey)
	}
	if !gotKey.Equal(wantKey) {
		t.Fatalf("fallback key doesn't match LeafKey([sni]) derivation")
	}
}

func TestCertFactory_Fallback_DeterministicAcrossCalls(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	c1, err := factory.Fallback(context.Background(), "flaky.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := factory.Fallback(context.Background(), "flaky.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf1, _ := x509.ParseCertificate(c1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Errorf("serial not deterministic: %v vs %v", leaf1.SerialNumber, leaf2.SerialNumber)
	}
	key1 := c1.PrivateKey.(*ecdsa.PrivateKey)
	key2 := c2.PrivateKey.(*ecdsa.PrivateKey)
	if !key1.Equal(key2) {
		t.Errorf("key not deterministic across repeated fallback mints for the same sni")
	}
}

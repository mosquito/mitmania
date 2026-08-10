package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"log/slog"
	"strings"
	"testing"
)

func TestCertFactory_SelfCert_FreshMintPersistsAndLogs(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck}, WithFactoryLogger(log))

	cn := "Friendly Name"
	san := "proxy.internal.example"
	names := []string{cn, san}
	tlsCert, err := factory.SelfCert(context.Background(), names)
	if err != nil {
		t.Fatalf("SelfCert: %v", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if leaf.Subject.CommonName != cn {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, cn)
	}
	// cn ("Friendly Name") has invalid dNSName syntax (a space) and must
	// be excluded from the SAN set entirely — only san should appear.
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != san {
		t.Errorf("DNSNames = %v, want [%s]", leaf.DNSNames, san)
	}
	if len(tlsCert.Certificate) != 2 {
		t.Fatalf("served chain has %d certs, want 2 (leaf + root)", len(tlsCert.Certificate))
	}
	root, err := x509.ParseCertificate(tlsCert.Certificate[1])
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}
	if !root.Equal(ca.Cert) {
		t.Errorf("chain[1] is not our root CA cert")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: san, Roots: roots}); err != nil {
		t.Fatalf("self-cert leaf does not validate against our root: %v", err)
	}

	wantKey, err := (DetKeyDeriver{ClusterKey: ck}).LeafKey([]string{"dns:" + san})
	if err != nil {
		t.Fatal(err)
	}
	gotKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("PrivateKey is %T, want *ecdsa.PrivateKey", tlsCert.PrivateKey)
	}
	if !gotKey.Equal(wantKey) {
		t.Fatalf("self-cert key doesn't match LeafKey([san]) derivation")
	}

	if !strings.Contains(buf.String(), "generated https-proxy certificate") {
		t.Errorf("expected an Info log line for the fresh mint, got: %s", buf.String())
	}
}

func TestCertFactory_SelfCert_CacheHitDoesNotReLog(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck}, WithFactoryLogger(log))

	const name = "Internal Proxy"
	if _, err := factory.SelfCert(context.Background(), []string{name}); err != nil {
		t.Fatalf("SelfCert (mint): %v", err)
	}
	if n := strings.Count(buf.String(), "generated https-proxy certificate"); n != 1 {
		t.Fatalf("mint logged %d times, want 1", n)
	}

	buf.Reset()
	c2, err := factory.SelfCert(context.Background(), []string{name})
	if err != nil {
		t.Fatalf("SelfCert (cache hit): %v", err)
	}
	if strings.Contains(buf.String(), "generated https-proxy certificate") {
		t.Errorf("cache hit re-logged the mint line: %s", buf.String())
	}
	if len(c2.Certificate) != 2 {
		t.Fatalf("cache-hit served chain has %d certs, want 2 (leaf + root)", len(c2.Certificate))
	}
}

func TestCertFactory_SelfCert_DeterministicAcrossCalls(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	c1, err := factory.SelfCert(context.Background(), []string{"Internal Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := factory.SelfCert(context.Background(), []string{"Internal Proxy"})
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
		t.Errorf("key not deterministic across repeated self-cert mints for the same name")
	}
}

func TestCertFactory_SelfCert_DifferentNamesProduceDifferentCerts(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	c1, err := factory.SelfCert(context.Background(), []string{"Internal Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := factory.SelfCert(context.Background(), []string{"proxy.internal.example"})
	if err != nil {
		t.Fatal(err)
	}
	leaf1, _ := x509.ParseCertificate(c1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Errorf("different names produced the same serial")
	}
	if leaf1.Subject.CommonName == leaf2.Subject.CommonName {
		t.Errorf("different names produced the same CommonName")
	}
}

func TestCertFactory_SelfCert_IPNameGetsIPAddressSAN(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	tlsCert, err := factory.SelfCert(context.Background(), []string{"10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IPAddresses = %v, want [10.0.0.5]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want none for an IP name", leaf.DNSNames)
	}
}

func TestCertFactory_SelfCert_MultipleCNsProduceFullSANSet(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	names := []string{"Friendly Name", "proxy.internal.example", "10.0.0.5"}
	tlsCert, err := factory.SelfCert(context.Background(), names)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != names[0] {
		t.Errorf("CommonName = %q, want %q (first ?cn= value)", leaf.Subject.CommonName, names[0])
	}
	// "Friendly Name" has invalid dNSName syntax (a space) and must be
	// excluded from the SAN set even though it's names[0] and becomes CN.
	wantDNS := []string{"proxy.internal.example"}
	if len(leaf.DNSNames) != len(wantDNS) {
		t.Fatalf("DNSNames = %v, want %v", leaf.DNSNames, wantDNS)
	}
	for i, want := range wantDNS {
		if leaf.DNSNames[i] != want {
			t.Errorf("DNSNames[%d] = %q, want %q", i, leaf.DNSNames[i], want)
		}
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.5" {
		t.Errorf("IPAddresses = %v, want [10.0.0.5]", leaf.IPAddresses)
	}

	// A cache hit must re-derive the identical leaf key from the SAME
	// identity ordering (DNSNames, then IPAddresses — SANStrings'
	// convention) that fresh-mint used, regardless of the original
	// ?cn= interleaving.
	c2, err := factory.SelfCert(context.Background(), names)
	if err != nil {
		t.Fatalf("SelfCert (cache hit): %v", err)
	}
	key1 := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	key2 := c2.PrivateKey.(*ecdsa.PrivateKey)
	if !key1.Equal(key2) {
		t.Errorf("cache-hit key doesn't match fresh-mint key for the same multi-cn identity")
	}
}

// TestCertFactory_SelfCert_DefaultNameStillMintsWithEmptySAN covers the
// --listen-https-proxy default (a single free-text "Internal Proxy" cn,
// no explicit ?cn=): it must still mint a servable cert rather than
// erroring, even though its SAN set ends up empty (only lenient,
// non-OpenSSL clients can verify it by hostname — the documented caveat
// from SelfCert's doc comment).
func TestCertFactory_SelfCert_DefaultNameStillMintsWithEmptySAN(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	tlsCert, err := factory.SelfCert(context.Background(), []string{"Internal Proxy"})
	if err != nil {
		t.Fatalf("SelfCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "Internal Proxy" {
		t.Errorf("CommonName = %q, want %q", leaf.Subject.CommonName, "Internal Proxy")
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Errorf("SAN set = DNS:%v IP:%v, want both empty for a syntactically invalid default cn", leaf.DNSNames, leaf.IPAddresses)
	}
}

// TestCertFactory_SelfCert_DifferentFreeTextCNsDontCollide guards the bug
// this design deliberately avoids: two distinct free-text-only CNs both
// filter down to an identical (empty) SAN identity, so the cache id must
// be disambiguated by something else (the raw names list feeding
// selfCertSerial) — otherwise the second mint would silently return the
// first's cached cert, with the WRONG CommonName.
func TestCertFactory_SelfCert_DifferentFreeTextCNsDontCollide(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	c1, err := factory.SelfCert(context.Background(), []string{"Internal Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := factory.SelfCert(context.Background(), []string{"My Other Proxy"})
	if err != nil {
		t.Fatal(err)
	}
	leaf1, _ := x509.ParseCertificate(c1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf1.Subject.CommonName == leaf2.Subject.CommonName {
		t.Fatalf("two different free-text CNs collided into the same cached cert (CommonName = %q both times)", leaf1.Subject.CommonName)
	}
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 {
		t.Errorf("two different free-text CNs produced the same serial")
	}
}

func TestIsValidDNSName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"proxy.internal.example", true},
		{"internal-proxy", true},
		{"10.0.0.5", true}, // digits/dots only is still LDH-valid as a label set
		{"Internal Proxy", false},
		{"", false},
		{"-leading-hyphen", false},
		{"trailing-hyphen-", false},
		{"has_underscore", false},
		{"has..empty..label", false},
		{strings.Repeat("a", 64) + ".example", false}, // label > 63
	}
	for _, c := range cases {
		if got := isValidDNSName(c.in); got != c.want {
			t.Errorf("isValidDNSName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

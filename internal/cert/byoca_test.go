package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// byoCert is one generated cert+key for BYO-CA test fixtures.
type byoCert struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

type rootOpts struct {
	curve          elliptic.Curve
	maxPathLen     int
	maxPathLenZero bool
	notBefore      time.Time
	notAfter       time.Time
	nonCriticalBC  bool // emit BasicConstraints as non-critical (via ExtraExtensions)
	noKeyCertSign  bool
}

func defaultRootOpts() rootOpts {
	return rootOpts{
		curve:     elliptic.P256(),
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour * 365),
	}
}

// selfSignedRoot builds a self-signed CA cert per opts.
func selfSignedRoot(t *testing.T, opts rootOpts) byoCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(opts.curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if opts.noKeyCertSign {
		keyUsage = x509.KeyUsageCRLSign
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            opts.maxPathLen,
		MaxPathLenZero:        opts.maxPathLenZero,
	}
	if opts.nonCriticalBC {
		bc, err := asn1MarshalBasicConstraints(true, opts.maxPathLen, opts.maxPathLenZero)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.BasicConstraintsValid = false // suppress the auto-generated (critical) one
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: oidBasicConstraints, Critical: false, Value: bc,
		})
		tmpl.IsCA = true // still logically a CA for our own bookkeeping, just via ExtraExtensions
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return byoCert{key: key, cert: cert}
}

// asn1MarshalBasicConstraints encodes a BasicConstraints extension value
// by hand, for constructing a deliberately non-critical one (Go's
// x509.CreateCertificate always emits it critical via the template's
// structured fields).
func asn1MarshalBasicConstraints(isCA bool, maxPathLen int, zero bool) ([]byte, error) {
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	bc := basicConstraints{IsCA: isCA, MaxPathLen: -1}
	if zero {
		bc.MaxPathLen = 0
	} else if maxPathLen >= 0 {
		bc.MaxPathLen = maxPathLen
	}
	return asn1.Marshal(bc)
}

// intermediateSignedBy builds a CA cert signed by parent.
func intermediateSignedBy(t *testing.T, parent byoCert, curve elliptic.Curve, maxPathLen int, maxPathLenZero bool) byoCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLenZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return byoCert{key: key, cert: cert}
}

func encodeCAP12(t *testing.T, signing byoCert, chain []*x509.Certificate, password string) []byte {
	t.Helper()
	certs := make([]*x509.Certificate, len(chain))
	copy(certs, chain)
	data, err := pkcs12.Modern.Encode(signing.key, signing.cert, certs, password)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func putCAP12(t *testing.T, dir string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "ca"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca", "ca.p12"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// --- Recipe A: self-signed BYO root ---

func TestBYOCA_RecipeA_SelfSignedRootLoads(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	root := selfSignedRoot(t, defaultRootOpts())
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if ca.Generated {
		t.Fatalf("Generated = true, want false for a loaded BYO root")
	}
	if !ca.Cert.Equal(root.cert) {
		t.Fatalf("loaded cert != supplied root cert")
	}
	if len(ca.Chain) != 0 {
		t.Fatalf("Chain = %d entries, want 0 for a self-signed root", len(ca.Chain))
	}
	if _, constrained := ca.issuanceBudget(); constrained {
		t.Fatalf("issuanceBudget: constrained = true, want false for an unconstrained root")
	}
}

func TestBYOCA_RecipeA_P384SigningKeyAccepted(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	opts := defaultRootOpts()
	opts.curve = elliptic.P384()
	root := selfSignedRoot(t, opts)
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA with a P-384 signing key: %v", err)
	}
}

// --- Recipe B: sub-CA signed by an org root, full chain in the bundle ---

func TestBYOCA_RecipeB_IntermediateWithCompleteChainLoads(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	orgRoot := selfSignedRoot(t, defaultRootOpts())
	sub := intermediateSignedBy(t, orgRoot, elliptic.P256(), 0, true) // pathlen:0
	putCAP12(t, dir, encodeCAP12(t, sub, []*x509.Certificate{orgRoot.cert}, p12Password(ck)))

	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if !ca.Cert.Equal(sub.cert) {
		t.Fatalf("loaded cert != supplied sub-CA cert")
	}
	if len(ca.Chain) != 0 {
		t.Fatalf("Chain = %d entries, want 0 (org root is the trust anchor, never sent)", len(ca.Chain))
	}
	budget, constrained := ca.issuanceBudget()
	if !constrained || budget != 0 {
		t.Fatalf("issuanceBudget = %d, constrained=%v; want 0, true (pathlen:0)", budget, constrained)
	}

	der := ca.ChainDER()
	if len(der) != 1 {
		t.Fatalf("ChainDER len = %d, want 1 (just the sub-CA — org root is never sent)", len(der))
	}
}

func TestBYOCA_RecipeB_MultiLevelChainPreserved(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	orgRoot := selfSignedRoot(t, defaultRootOpts())
	mid := intermediateSignedBy(t, orgRoot, elliptic.P256(), 1, false) // pathlen:1, between root and our sub
	sub := intermediateSignedBy(t, mid, elliptic.P256(), 0, true)      // pathlen:0
	putCAP12(t, dir, encodeCAP12(t, sub, []*x509.Certificate{orgRoot.cert, mid.cert}, p12Password(ck)))

	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if len(ca.Chain) != 1 || !ca.Chain[0].Equal(mid.cert) {
		t.Fatalf("Chain = %v, want [mid] (the org root excluded, mid included)", ca.Chain)
	}
	der := ca.ChainDER()
	if len(der) != 2 {
		t.Fatalf("ChainDER len = %d, want 2 (sub-CA + mid, org root never sent)", len(der))
	}
}

func TestBYOCA_RecipeB_MissingRootInBundleFailsStart(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	orgRoot := selfSignedRoot(t, defaultRootOpts())
	sub := intermediateSignedBy(t, orgRoot, elliptic.P256(), 0, true)
	// Bundle carries only the sub-CA, no chain up to a self-signed root.
	putCAP12(t, dir, encodeCAP12(t, sub, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for an intermediate with no chain to a root")
	}
}

// --- Recipe C: same key, re-issued cert (exercised at the LoadOrGenerateCA level for the .tuple wipe) ---

func TestBYOCA_RecipeC_SameKeyReissuedCertWipesLeafOnNextLoad(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts1 := defaultRootOpts()
	root1 := selfSignedRootFromKey(t, key, opts1)
	putCAP12(t, dir, encodeCAP12(t, root1, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA (initial): %v", err)
	}

	sentinel := filepath.Join(dir, "leaf", "by-id", "sentinel")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Re-issue: SAME key, different pathLenConstraint — this is Recipe
	// C's "get your org to sign the key mitmania already generated"
	// scenario reduced to its essential shape (same key, new cert).
	opts2 := defaultRootOpts()
	opts2.maxPathLenZero = true
	root2 := selfSignedRootFromKey(t, key, opts2)
	putCAP12(t, dir, encodeCAP12(t, root2, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA (reissued): %v", err)
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("leaf/ was not wiped after a same-key, different-cert CA swap (stat err = %v)", err)
	}
}

func selfSignedRootFromKey(t *testing.T, key *ecdsa.PrivateKey, opts rootOpts) byoCert {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            opts.maxPathLen,
		MaxPathLenZero:        opts.maxPathLenZero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return byoCert{key: key, cert: cert}
}

// --- Validation rejections ---

func TestBYOCA_RejectsRSASigningKey(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RSA Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern.Encode(rsaKey, cert, nil, p12Password(ck))
	if err != nil {
		t.Fatal(err)
	}
	putCAP12(t, dir, data)

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for an RSA signing key")
	}
}

func TestBYOCA_RejectsNonCACert(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Not A CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour * 365),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// BasicConstraintsValid deliberately false/omitted: not a CA cert.
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern.Encode(key, cert, nil, p12Password(ck))
	if err != nil {
		t.Fatal(err)
	}
	putCAP12(t, dir, data)

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for a non-CA cert")
	}
}

func TestBYOCA_RejectsMissingKeyCertSign(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	opts := defaultRootOpts()
	opts.noKeyCertSign = true
	root := selfSignedRoot(t, opts)
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for KeyUsage missing keyCertSign")
	}
}

func TestBYOCA_RejectsExpiredCert(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	opts := defaultRootOpts()
	opts.notBefore = time.Now().Add(-48 * time.Hour)
	opts.notAfter = time.Now().Add(-24 * time.Hour)
	root := selfSignedRoot(t, opts)
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for an expired signing cert")
	}
}

func TestBYOCA_RejectsNotYetValidCert(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	opts := defaultRootOpts()
	opts.notBefore = time.Now().Add(24 * time.Hour)
	opts.notAfter = time.Now().Add(48 * time.Hour)
	root := selfSignedRoot(t, opts)
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err == nil {
		t.Fatalf("expected a fail-start error for a not-yet-valid signing cert")
	}
}

func TestBYOCA_RejectsNonCriticalBasicConstraints(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	opts := defaultRootOpts()
	opts.nonCriticalBC = true
	root := selfSignedRoot(t, opts)
	putCAP12(t, dir, encodeCAP12(t, root, nil, p12Password(ck)))

	_, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err == nil {
		t.Fatalf("expected a fail-start error for a non-critical BasicConstraints extension")
	}
	if !strings.Contains(err.Error(), "critical") {
		t.Fatalf("error = %v, want it to mention criticality", err)
	}
}

package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// realFixture is a synthetically-built "real" chain (root -> intermediate ->
// leaf) standing in for what a TLS handshake's PeerCertificates would give
// us. Building it via x509.CreateCertificate + ParseCertificate (rather than
// hand-populating a Certificate struct) is what makes RawIssuer,
// RawSubjectPublicKeyInfo, and Extensions realistic.
type realFixture struct {
	rootKey *ecdsa.PrivateKey
	root    *x509.Certificate
	intKey  *ecdsa.PrivateKey
	int     *x509.Certificate
	leafKey *ecdsa.PrivateKey
	leaf    *x509.Certificate
}

func buildRealFixture(t *testing.T, mutateLeaf func(*x509.Certificate)) realFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Real Test Root"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365 * 10),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Real Test Intermediate"},
		NotBefore:             time.Now().Add(-12 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365 * 5),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, root, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediate, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com", "*.example.com", "alt.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Fields that must NOT survive cloning (stripped by cloneTemplate's allow-list copy):
		OCSPServer:            []string{"http://ocsp.real-ca.example/"},
		IssuingCertificateURL: []string{"http://aia.real-ca.example/int.crt"},
		CRLDistributionPoints: []string{"http://crl.real-ca.example/int.crl"},
	}
	if mutateLeaf != nil {
		mutateLeaf(leafTmpl)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return realFixture{
		rootKey: rootKey, root: root,
		intKey: intKey, int: intermediate,
		leafKey: leafKey, leaf: leaf,
	}
}

func testCA(t *testing.T) (*CA, []byte) {
	t.Helper()
	ck := testClusterKey()
	st := testPosixStorage(t, t.TempDir())
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	return ca, ck
}

func TestCloneChain_FullChainValidatesAgainstOurRoot(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}

	realChain := []*x509.Certificate{fx.leaf, fx.int} // leaf-first, no root
	synth, synthKeys, err := CloneChain(ca, keys, realChain)
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if len(synth) != 2 || len(synthKeys) != 2 {
		t.Fatalf("CloneChain returned %d certs, %d keys, want 2/2", len(synth), len(synthKeys))
	}

	synthLeaf, synthInt := synth[0], synth[1]

	// Identity fields copied verbatim.
	if synthLeaf.Subject.CommonName != fx.leaf.Subject.CommonName {
		t.Errorf("Subject.CommonName = %q, want %q", synthLeaf.Subject.CommonName, fx.leaf.Subject.CommonName)
	}
	if !synthLeaf.NotBefore.Equal(fx.leaf.NotBefore) || !synthLeaf.NotAfter.Equal(fx.leaf.NotAfter) {
		t.Errorf("validity not copied verbatim: got [%v,%v], want [%v,%v]",
			synthLeaf.NotBefore, synthLeaf.NotAfter, fx.leaf.NotBefore, fx.leaf.NotAfter)
	}
	if synthLeaf.KeyUsage != fx.leaf.KeyUsage {
		t.Errorf("KeyUsage = %v, want %v", synthLeaf.KeyUsage, fx.leaf.KeyUsage)
	}
	wantDNS := []string{"leaf.example.com", "*.example.com", "alt.example.com"}
	if len(synthLeaf.DNSNames) != len(wantDNS) {
		t.Fatalf("DNSNames = %v, want %v", synthLeaf.DNSNames, wantDNS)
	}
	for i, n := range wantDNS {
		if synthLeaf.DNSNames[i] != n {
			t.Errorf("DNSNames[%d] = %q, want %q (order must be preserved)", i, synthLeaf.DNSNames[i], n)
		}
	}
	if len(synthLeaf.IPAddresses) != 1 || !synthLeaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", synthLeaf.IPAddresses)
	}

	// Fields stripped by cloneTemplate's allow-list copy.
	if len(synthLeaf.OCSPServer) != 0 {
		t.Errorf("OCSPServer leaked into clone: %v", synthLeaf.OCSPServer)
	}
	if len(synthLeaf.IssuingCertificateURL) != 0 {
		t.Errorf("IssuingCertificateURL (AIA) leaked into clone: %v", synthLeaf.IssuingCertificateURL)
	}
	if len(synthLeaf.CRLDistributionPoints) != 0 {
		t.Errorf("CRLDistributionPoints leaked into clone: %v", synthLeaf.CRLDistributionPoints)
	}

	// Intermediate CA constraints preserved.
	if !synthInt.IsCA || !synthInt.BasicConstraintsValid {
		t.Errorf("synthetic intermediate lost CA constraints: IsCA=%v BasicConstraintsValid=%v", synthInt.IsCA, synthInt.BasicConstraintsValid)
	}
	if synthInt.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("synthetic intermediate missing KeyUsageCertSign")
	}

	// AKI chaining: leaf's AKI == intermediate's SKI; intermediate's AKI == root's SKI.
	if len(synthLeaf.AuthorityKeyId) == 0 || string(synthLeaf.AuthorityKeyId) != string(synthInt.SubjectKeyId) {
		t.Errorf("synthetic leaf AuthorityKeyId (%x) != intermediate SubjectKeyId (%x)", synthLeaf.AuthorityKeyId, synthInt.SubjectKeyId)
	}
	if len(synthInt.AuthorityKeyId) == 0 || string(synthInt.AuthorityKeyId) != string(ca.Cert.SubjectKeyId) {
		t.Errorf("synthetic intermediate AuthorityKeyId (%x) != root SubjectKeyId (%x)", synthInt.AuthorityKeyId, ca.Cert.SubjectKeyId)
	}

	// The client re-validates the synthetic chain against only our root and
	// must succeed, at exactly the point the real chain would.
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	inters := x509.NewCertPool()
	inters.AddCert(synthInt)
	if _, err := synthLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Errorf("synthetic chain failed to verify against our root: %v", err)
	}
}

func TestCloneChain_ExpiredRealLeafStaysExpiredSynthetically(t *testing.T) {
	fx := buildRealFixture(t, func(tmpl *x509.Certificate) {
		tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
		tmpl.NotAfter = time.Now().Add(-24 * time.Hour) // already expired
	})
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}

	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	inters := x509.NewCertPool()
	inters.AddCert(synth[1])
	_, err = synth[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters})
	if err == nil {
		t.Fatalf("expected synthetic leaf to fail verification as expired, got nil error")
	}
	if _, ok := err.(x509.CertificateInvalidError); !ok {
		t.Fatalf("expected x509.CertificateInvalidError (Expired), got %T: %v", err, err)
	}
}

func TestCloneChain_SingleElementChainSignedDirectlyByRoot(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}

	// No intermediate in the real chain: leaf is signed directly by our root.
	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if len(synth) != 1 {
		t.Fatalf("CloneChain returned %d certs, want 1", len(synth))
	}
	if string(synth[0].AuthorityKeyId) != string(ca.Cert.SubjectKeyId) {
		t.Errorf("leaf AuthorityKeyId != root SubjectKeyId when signed directly by root")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := synth[0].Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("directly-root-signed synthetic leaf failed to verify: %v", err)
	}
}

func TestCloneChain_SerialAndKeyDeterministicAcrossCalls(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}

	realChain := []*x509.Certificate{fx.leaf, fx.int}
	synth1, keys1, err := CloneChain(ca, keys, realChain)
	if err != nil {
		t.Fatalf("CloneChain (1st): %v", err)
	}
	synth2, keys2, err := CloneChain(ca, keys, realChain)
	if err != nil {
		t.Fatalf("CloneChain (2nd): %v", err)
	}

	// Serial numbers are formula-derived, not random: must match exactly.
	if synth1[0].SerialNumber.Cmp(synth2[0].SerialNumber) != 0 {
		t.Errorf("leaf serial not deterministic: %v vs %v", synth1[0].SerialNumber, synth2[0].SerialNumber)
	}
	if synth1[1].SerialNumber.Cmp(synth2[1].SerialNumber) != 0 {
		t.Errorf("intermediate serial not deterministic: %v vs %v", synth1[1].SerialNumber, synth2[1].SerialNumber)
	}
	// Keys are HKDF-derived, not random: must be the same key both times.
	if !keys1[0].Equal(keys2[0]) {
		t.Errorf("leaf key not deterministic across CloneChain calls")
	}
	if !keys1[1].Equal(keys2[1]) {
		t.Errorf("intermediate key not deterministic across CloneChain calls")
	}
	// Note: synth1[i].Equal(synth2[i]) is deliberately not asserted — ECDSA
	// signatures use a random nonce, so the DER bytes legitimately differ
	// between calls even though everything else (the deterministically
	// derived key material and serial) matches.
}

func TestCloneChain_EmptyChainErrors(t *testing.T) {
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}
	if _, _, err := CloneChain(ca, keys, nil); err == nil {
		t.Fatalf("CloneChain(nil): expected error, got nil")
	}
}

// --- flattening under a constrained bring-your-own signing CA ---

// constrainedTestCA is testCA but with the given issuance budget baked
// into the (self-signed, for simplicity) signing cert's own
// BasicConstraints pathLenConstraint — standing in for a bring-your-own
// sub-CA without needing the full PKCS#12/DecodeChain plumbing byoca_test.go
// exercises separately.
func constrainedTestCA(t *testing.T, maxPathLen int, zero bool) *CA {
	t.Helper()
	root := selfSignedRoot(t, rootOpts{
		curve: elliptic.P256(), notBefore: time.Now().Add(-time.Hour),
		notAfter: time.Now().Add(24 * time.Hour * 365), maxPathLen: maxPathLen, maxPathLenZero: zero,
	})
	return &CA{Cert: root.cert, Key: root.key}
}

func TestCloneChain_Flattens_WhenRealChainExceedsBudget(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca := constrainedTestCA(t, 0, true) // pathlen:0 — leaves only
	keys := DetKeyDeriver{ClusterKey: testClusterKey()}

	realChain := []*x509.Certificate{fx.leaf, fx.int} // one intermediate; budget is 0
	synth, synthKeys, err := CloneChain(ca, keys, realChain)
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if len(synth) != 1 || len(synthKeys) != 1 {
		t.Fatalf("CloneChain returned %d certs, %d keys, want 1/1 (flattened)", len(synth), len(synthKeys))
	}
	if synth[0].Subject.CommonName != fx.leaf.Subject.CommonName {
		t.Errorf("flattened leaf identity = %q, want %q", synth[0].Subject.CommonName, fx.leaf.Subject.CommonName)
	}
	if string(synth[0].AuthorityKeyId) != string(ca.Cert.SubjectKeyId) {
		t.Errorf("flattened leaf AuthorityKeyId != signing CA SubjectKeyId — not signed directly by it")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := synth[0].Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("flattened leaf failed to verify directly against the signing CA: %v", err)
	}
}

func TestCloneChain_DoesNotFlatten_WhenRealChainFitsBudget(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca := constrainedTestCA(t, 1, false) // pathlen:1 — exactly covers one intermediate
	keys := DetKeyDeriver{ClusterKey: testClusterKey()}

	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if len(synth) != 2 {
		t.Fatalf("CloneChain returned %d certs, want 2 (budget covers the one intermediate, no flattening)", len(synth))
	}
}

func TestCloneChain_UnconstrainedRootNeverFlattens(t *testing.T) {
	fx := buildRealFixture(t, nil)
	ca, ck := testCA(t) // the ordinary auto-generated, unconstrained root
	keys := DetKeyDeriver{ClusterKey: ck}

	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if len(synth) != 2 {
		t.Fatalf("CloneChain returned %d certs, want 2 (unconstrained root, no flattening)", len(synth))
	}
}

func TestCloneChain_FlattenedLeafNotAfterClampedToSigningCA(t *testing.T) {
	ca := constrainedTestCA(t, 0, true) // pathlen:0, expires in ~1 year (see constrainedTestCA)
	fx := buildRealFixture(t, func(tmpl *x509.Certificate) {
		tmpl.NotAfter = ca.Cert.NotAfter.Add(365 * 24 * time.Hour) // real leaf outlives the signing CA
	})
	keys := DetKeyDeriver{ClusterKey: testClusterKey()}

	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if !synth[0].NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("flattened leaf NotAfter = %v, want clamped to signing CA's %v", synth[0].NotAfter, ca.Cert.NotAfter)
	}
}

func TestCloneChain_UnflattenedLeafNotAfterNotClampedByIntermediate(t *testing.T) {
	// Sanity check that clamping is specifically about whatever's signed
	// DIRECTLY by the signing CA — an intermediate's own (later) NotAfter
	// does not get clamped onto the leaf beneath it in the unconstrained
	// case; only the top-level element touching ca.Cert is ever clamped.
	fx := buildRealFixture(t, nil)
	ca, ck := testCA(t)
	keys := DetKeyDeriver{ClusterKey: ck}

	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	if !synth[0].NotAfter.Equal(fx.leaf.NotAfter) {
		t.Fatalf("leaf NotAfter = %v, want the real leaf's own %v (unconstrained root, not clamped)", synth[0].NotAfter, fx.leaf.NotAfter)
	}
}

// TestTypeTaggedSANStrings_DNSNameLookingLikeIPDoesNotCollideWithRealIP is
// exactly the collision type-tagged SAN salting exists to prevent: a DNSName
// that happens to be a valid IP literal string must derive a DIFFERENT
// leaf key than an actual IPAddress SAN with the same text, since an
// untagged salt would hash both to the identical "1.2.3.4" string.
func TestTypeTaggedSANStrings_DNSNameLookingLikeIPDoesNotCollideWithRealIP(t *testing.T) {
	dnsLeaf := &x509.Certificate{DNSNames: []string{"1.2.3.4"}}
	ipLeaf := &x509.Certificate{IPAddresses: []net.IP{net.ParseIP("1.2.3.4")}}

	dnsTagged := typeTaggedSANStrings(dnsLeaf)
	ipTagged := typeTaggedSANStrings(ipLeaf)
	if len(dnsTagged) != 1 || len(ipTagged) != 1 || dnsTagged[0] == ipTagged[0] {
		t.Fatalf("typeTaggedSANStrings produced colliding tags: dns=%v ip=%v", dnsTagged, ipTagged)
	}

	ck := testClusterKey()
	keys := DetKeyDeriver{ClusterKey: ck}
	dnsKey, err := keys.LeafKey(dnsTagged)
	if err != nil {
		t.Fatal(err)
	}
	ipKey, err := keys.LeafKey(ipTagged)
	if err != nil {
		t.Fatal(err)
	}
	if dnsKey.Equal(ipKey) {
		t.Fatalf("a DNSName that looks like an IP literal derived the same leaf key as an actual IP SAN")
	}
}

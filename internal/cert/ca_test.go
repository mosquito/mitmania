package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mitmania/internal/storage"
)

func testPosixStorage(t *testing.T, dir string) storage.Storage {
	t.Helper()
	st, err := storage.NewPosixStorage(dir)
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	return st
}

func TestLoadOrGenerateCA_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	ca1, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if !ca1.Cert.IsCA {
		t.Fatalf("generated root is not marked IsCA")
	}

	if _, err := os.Stat(filepath.Join(dir, "ca", "ca.p12")); err != nil {
		t.Fatalf("ca.p12 not persisted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".tuple")); err != nil {
		t.Fatalf(".tuple not written: %v", err)
	}

	ca2, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (reload): %v", err)
	}
	if !ca1.Cert.Equal(ca2.Cert) {
		t.Fatalf("reloaded root cert differs from generated one")
	}
	if !ca1.Key.Equal(ca2.Key) {
		t.Fatalf("reloaded root key differs from generated one")
	}
}

func TestLoadOrGenerateCA_WrongClusterKeyFailsStart(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	if _, err := LoadOrGenerateCA(context.Background(), st, testClusterKey()); err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	wrongKey := bytes.Repeat([]byte{0x99}, 32)
	if _, err := LoadOrGenerateCA(context.Background(), st, wrongKey); err == nil {
		t.Fatalf("LoadOrGenerateCA with wrong clusterKey: expected error, got nil")
	}
}

func TestLoadOrGenerateCA_TupleMismatchWipesLeaf(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	leafDir := filepath.Join(dir, "leaf")
	if err := os.MkdirAll(leafDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(leafDir, "by-id", "sentinel")
	if err := os.MkdirAll(filepath.Dir(sentinel), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Corrupt .tuple directly to simulate an out-of-band root swap without
	// touching ca.p12 (a wrong-password reload is already covered above and
	// would fail-start before ever reaching the tuple check).
	tuplePath := filepath.Join(dir, ".tuple")
	if err := os.WriteFile(tuplePath, []byte("not-the-real-tuple"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA (tuple mismatch): %v", err)
	}

	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("leaf/ was not wiped after .tuple mismatch (stat err = %v)", err)
	}
}

func TestLoadOrGenerateCA_FreshGenerationWipesExistingLeaf(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()

	leafDir := filepath.Join(dir, "leaf")
	sentinel := filepath.Join(leafDir, "stale.p12")
	if err := os.MkdirAll(leafDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerateCA(context.Background(), st, ck); err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("leaf/ was not wiped on fresh root generation (stat err = %v)", err)
	}
}

func TestTupleHashChangesWithClusterKey(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ca, err := LoadOrGenerateCA(context.Background(), st, testClusterKey())
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	h1 := tupleHash(ca.Cert, testClusterKey())
	h2 := tupleHash(ca.Cert, bytes.Repeat([]byte{0x01}, 32))
	if bytes.Equal(h1, h2) {
		t.Fatalf("tupleHash did not change with clusterKey")
	}
}

// TestTupleHashFoldsInCloneFormatVersion verifies the .tuple formula
// actually includes cloneFormatVersion, not just the signing cert/
// clusterKeyID — a manually-computed hash omitting it must NOT match
// tupleHash's real output, otherwise a future cloneFormatVersion bump
// would silently fail to trigger the leaf/ wipe a rolling upgrade relies
// on.
func TestTupleHashFoldsInCloneFormatVersion(t *testing.T) {
	st := testPosixStorage(t, t.TempDir())
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	got := tupleHash(ca.Cert, ck)

	keyID := sha256.Sum256(ck)
	h := sha256.New()
	h.Write(ca.Cert.Raw)
	h.Write(keyID[:])
	withoutVersion := h.Sum(nil)

	if bytes.Equal(got, withoutVersion) {
		t.Fatalf("tupleHash matches a computation that omits cloneFormatVersion — it isn't actually folded in")
	}
}

// TestTupleHashChangesOnSameKeyDifferentCert verifies the bring-your-own
// signing CA re-issuance scenario: an operator reuses the SAME signing
// key but swaps in a re-issued cert (e.g. a different pathLenConstraint
// or validity window)
// — tupleHash must change even though the key, and hence the cert's
// SubjectPublicKeyInfo, is identical, otherwise leaf/ would never get
// wiped and already-cached leaves would keep being served under the OLD
// cert's policy (flatten/clamp decisions made at mint time) instead of
// the new one.
func TestTupleHashChangesOnSameKeyDifferentCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certA := selfSignedRootWithPathLen(t, key, -1, false) // unconstrained
	certB := selfSignedRootWithPathLen(t, key, 0, true)   // pathlen:0, same key

	if !certA.PublicKey.(*ecdsa.PublicKey).Equal(certB.PublicKey.(*ecdsa.PublicKey)) {
		t.Fatalf("test fixture bug: certA/certB don't actually share a public key")
	}

	ck := testClusterKey()
	if bytes.Equal(tupleHash(certA, ck), tupleHash(certB, ck)) {
		t.Fatalf("tupleHash unchanged across a same-key, different-cert re-issuance — leaf/ would never be wiped on a Recipe C CA swap")
	}
}

// selfSignedRootWithPathLen builds a self-signed CA cert for key with the
// given pathLenConstraint (maxPathLen ignored when zero is true).
func selfSignedRootWithPathLen(t *testing.T, key *ecdsa.PrivateKey, maxPathLen int, zero bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        zero,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

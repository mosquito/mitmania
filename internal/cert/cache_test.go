package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"mitmania/internal/storage"
)

// selfSignedCert builds a self-signed CA cert with a distinct Subject —
// unlike buildRealFixture's root, which uses a fixed CommonName, so two
// independently-built fixtures' roots collide on Subject/RawSubject and
// aren't actually "unrelated" for orderChainLeafFirst's purposes (it
// matches by RawIssuer/RawSubject string equality, not signature
// validity).
func selfSignedCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
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

// stubStorage wraps a real Storage and lets a test inject a specific
// operation failure. mitmania's only Storage backend (PosixStorage) has
// no way to fail Get/Put/List/DeletePrefix mid-operation on demand, but
// cache.go's error-wrapping branches around those calls are exactly the
// fail-closed behavior CLAUDE.md asks to be proven, not just the happy
// path — so a fault-injecting wrapper is the only way to reach them.
type stubStorage struct {
	storage.Storage
	getErr          error
	getErrKey       string // empty means "fail every Get"
	putErr          error
	listErr         error
	deletePrefixErr error
}

func (s *stubStorage) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	if s.getErr != nil && (s.getErrKey == "" || s.getErrKey == key) {
		return nil, "", s.getErr
	}
	return s.Storage.Get(ctx, key)
}

func (s *stubStorage) Put(ctx context.Context, key string, data []byte) error {
	if s.putErr != nil {
		return s.putErr
	}
	return s.Storage.Put(ctx, key, data)
}

func (s *stubStorage) List(ctx context.Context, prefix string) ([]storage.Entry, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.Storage.List(ctx, prefix)
}

func (s *stubStorage) DeletePrefix(ctx context.Context, prefix string) error {
	if s.deletePrefixErr != nil {
		return s.deletePrefixErr
	}
	return s.Storage.DeletePrefix(ctx, prefix)
}

// noLinkerStorage deliberately does NOT satisfy storage.Linker: Symlink
// isn't part of the storage.Storage interface, so embedding the
// interface VALUE (as opposed to a concrete *PosixStorage) doesn't
// promote it, unlike stubStorage above which embeds the same interface
// for the same reason. Stands in for a backend (e.g. an S3-style one)
// with no Linker equivalent.
type noLinkerStorage struct {
	storage.Storage
}

// failSymlinkStorage always fails Symlink, to exercise ensureLinks' and
// symlink's error-wrapping paths without needing a backend that can
// genuinely fail one.
type failSymlinkStorage struct {
	storage.Storage
	err error
}

func (f failSymlinkStorage) Symlink(ctx context.Context, key, targetKey string) error {
	return f.err
}

// fsPath converts a Storage key (certKey/nameKey's "/"-delimited output)
// into the real filesystem path PosixStorage maps it to, for tests that
// assert directly against the disk.
func fsPath(dir, key string) string {
	return filepath.Join(dir, filepath.FromSlash(key))
}

func TestCertFactory_MintThenServeFromCache(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}

	id := cache.IDFor(realChain)
	if _, err := os.Stat(fsPath(dir, certKey(id))); !os.IsNotExist(err) {
		t.Fatalf("certs/ file exists before first mint (stat err = %v)", err)
	}

	tlsCert1, err := factory.For(ctx, "leaf.example.com", realChain)
	if err != nil {
		t.Fatalf("For (mint): %v", err)
	}
	// leaf + intermediate, plus the signing CA appended on the wire.
	if len(tlsCert1.Certificate) != 3 {
		t.Fatalf("Certificate chain len = %d, want 3", len(tlsCert1.Certificate))
	}
	if _, err := os.Stat(fsPath(dir, certKey(id))); err != nil {
		t.Fatalf("certs/ file not persisted after mint: %v", err)
	}
	nameLink := fsPath(dir, nameKey(nameID(cache.namespace, "leaf.example.com")))
	if _, err := os.Stat(nameLink); err != nil {
		t.Fatalf("exact-SAN symlink not created: %v", err)
	}

	tlsCert2, err := factory.For(ctx, "leaf.example.com", realChain)
	if err != nil {
		t.Fatalf("For (cache hit): %v", err)
	}
	leaf1, err := x509.ParseCertificate(tlsCert1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := x509.ParseCertificate(tlsCert2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if !leaf1.Equal(leaf2) {
		t.Fatalf("cache hit returned a different cert than the mint (should be byte-identical, no re-signing)")
	}
}

// TestCertFactory_WildcardSANGetsSymlinkToo verifies wildcard SANs aren't
// special-cased: since names/ entries are hashed rather than stored as
// literal filenames, a bare "*" is no different from any other name, and
// gets a names/ symlink to the same certs/ entry as everything else.
func TestCertFactory_WildcardSANGetsSymlinkToo(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	fx := buildRealFixture(t, nil) // includes DNSNames with "*.example.com"
	if _, err := factory.For(ctx, "wild.example.com", []*x509.Certificate{fx.leaf, fx.int}); err != nil {
		t.Fatalf("For: %v", err)
	}

	wantID := cache.IDFor([]*x509.Certificate{fx.leaf, fx.int})
	wildcardLink := fsPath(dir, nameKey(nameID(cache.namespace, "*.example.com")))
	target, err := os.Readlink(wildcardLink)
	if err != nil {
		t.Fatalf("wildcard SAN should get a names/ symlink like any other name: %v", err)
	}
	gotPath, err := filepath.Abs(filepath.Join(filepath.Dir(wildcardLink), target))
	if err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.Abs(fsPath(dir, certKey(wantID)))
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != wantPath {
		t.Fatalf("wildcard symlink target = %s, want %s", gotPath, wantPath)
	}
}

func TestCertFactory_ReMintsOnSerialChange(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	fx1 := buildRealFixture(t, nil)
	realChain1 := []*x509.Certificate{fx1.leaf, fx1.int}
	tlsCert1, err := factory.For(ctx, "leaf.example.com", realChain1)
	if err != nil {
		t.Fatalf("For (1st): %v", err)
	}

	// Same SAN set, but a re-issued real leaf with a new serial (renewal —
	// no real CA reuses a serial for different cert content). The cache
	// address folds in the real chain's DER fingerprint (which includes
	// the serial), so this must be a cache miss and a fresh mint, not a
	// stale hit — the leaf *key* stays stable regardless (salt = SANs
	// only).
	fx2 := buildRealFixture(t, func(c *x509.Certificate) { c.SerialNumber = big.NewInt(999) })
	realChain2 := []*x509.Certificate{fx2.leaf, fx2.int}
	if fx1.leaf.SerialNumber.Cmp(fx2.leaf.SerialNumber) == 0 {
		t.Fatalf("test fixtures unexpectedly share a serial")
	}

	tlsCert2, err := factory.For(ctx, "leaf.example.com", realChain2)
	if err != nil {
		t.Fatalf("For (renewed): %v", err)
	}

	leaf1, err := x509.ParseCertificate(tlsCert1.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := x509.ParseCertificate(tlsCert2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf1.Equal(leaf2) {
		t.Fatalf("renewed real leaf (new serial) served the stale cached clone instead of re-minting")
	}
	if leaf2.SerialNumber.Cmp(serialFor(fx2.leaf)) != 0 {
		t.Fatalf("re-minted clone's serial doesn't match serialFor(fx2.leaf)")
	}

	// Leaf key must be unchanged across the re-mint (salt = SANs, same both times).
	leafKey, err := (DetKeyDeriver{ClusterKey: ck}).LeafKey(typeTaggedSANStrings(fx2.leaf))
	if err != nil {
		t.Fatal(err)
	}
	gotKey, ok := tlsCert2.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("tlsCert2.PrivateKey is %T, want *ecdsa.PrivateKey", tlsCert2.PrivateKey)
	}
	if !gotKey.Equal(leafKey) {
		t.Fatalf("leaf key changed across re-mint despite identical SAN set")
	}
}

func TestCertFactory_SingleflightCoalescesConcurrentMints(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}

	const n = 20
	var wg sync.WaitGroup
	var errCount atomic.Int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := factory.For(ctx, "leaf.example.com", realChain); err != nil {
				errCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if errCount.Load() != 0 {
		t.Fatalf("%d/%d concurrent For() calls errored", errCount.Load(), n)
	}
	// singleflight only coalesces calls that overlap in time; it does not
	// guarantee the on-disk file is written exactly once under a race
	// between distinct Do() waves. What must hold is that all callers got a
	// consistent, non-corrupt result — verified by the zero error count
	// above — and that a cache entry now exists.
	id := cache.IDFor(realChain)
	if _, err := os.Stat(fsPath(dir, certKey(id))); err != nil {
		t.Fatalf("certs/ file missing after concurrent mints: %v", err)
	}
}

func TestOrderChainLeafFirst(t *testing.T) {
	fx := buildRealFixture(t, nil)
	st := testPosixStorage(t, t.TempDir())
	ca, err := LoadOrGenerateCA(context.Background(), st, testClusterKey())
	if err != nil {
		t.Fatal(err)
	}
	keys := DetKeyDeriver{ClusterKey: testClusterKey()}
	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatal(err)
	}

	// Feed the ordering function the reverse of the expected order and
	// confirm it recovers leaf-first regardless of input order.
	reversed := []*x509.Certificate{synth[1], synth[0]}
	ordered, err := orderChainLeafFirst(reversed)
	if err != nil {
		t.Fatalf("orderChainLeafFirst: %v", err)
	}
	if len(ordered) != 2 || !ordered[0].Equal(synth[0]) || !ordered[1].Equal(synth[1]) {
		t.Fatalf("orderChainLeafFirst did not recover leaf-first order")
	}
}

func TestOrderChainLeafFirst_SingleElement(t *testing.T) {
	fx := buildRealFixture(t, nil)
	st := testPosixStorage(t, t.TempDir())
	ca, err := LoadOrGenerateCA(context.Background(), st, testClusterKey())
	if err != nil {
		t.Fatal(err)
	}
	keys := DetKeyDeriver{ClusterKey: testClusterKey()}
	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf})
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := orderChainLeafFirst(synth)
	if err != nil {
		t.Fatalf("orderChainLeafFirst: %v", err)
	}
	if len(ordered) != 1 || !ordered[0].Equal(synth[0]) {
		t.Fatalf("orderChainLeafFirst mishandled a single-element chain")
	}
}

func TestCertCache_CountAndFlush(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)
	factory := NewCertFactory(ca, cache, DetKeyDeriver{ClusterKey: ck})

	if n, err := cache.Count(ctx); err != nil || n != 0 {
		t.Fatalf("Count() = %d, %v; want 0, nil", n, err)
	}

	fx := buildRealFixture(t, nil)
	if _, err := factory.For(ctx, "leaf.example.com", []*x509.Certificate{fx.leaf, fx.int}); err != nil {
		t.Fatalf("For: %v", err)
	}
	if n, err := cache.Count(ctx); err != nil || n != 1 {
		t.Fatalf("Count() = %d, %v; want 1, nil", n, err)
	}

	if err := cache.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if n, err := cache.Count(ctx); err != nil || n != 0 {
		t.Fatalf("Count() after Flush = %d, %v; want 0, nil", n, err)
	}
	nameLink := fsPath(dir, nameKey(nameID(cache.namespace, "leaf.example.com")))
	if _, err := os.Stat(nameLink); !os.IsNotExist(err) {
		t.Fatalf("symlink survived Flush (stat err = %v)", err)
	}

	// Flush must leave the cache usable, not just empty.
	if _, err := factory.For(ctx, "leaf.example.com", []*x509.Certificate{fx.leaf, fx.int}); err != nil {
		t.Fatalf("For after Flush: %v", err)
	}
	if n, err := cache.Count(ctx); err != nil || n != 1 {
		t.Fatalf("Count() after re-mint = %d, %v; want 1, nil", n, err)
	}
}

// cachableChain mints an actual CloneChain output (properly keyed and
// signed by ca) for tests that call cache.put/get directly rather than
// going through CertFactory — since verify-on-hit now checks every
// hit re-derives the right leaf key AND chains to ca, a raw unsigned
// fixture chain (buildRealFixture's output, signed by its own fake root)
// would never pass; only an actually-cloned chain does.
func cachableChain(t *testing.T, ca *CA, ck []byte, fx realFixture) []*x509.Certificate {
	t.Helper()
	keys := DetKeyDeriver{ClusterKey: ck}
	synth, _, err := CloneChain(ca, keys, []*x509.Certificate{fx.leaf, fx.int})
	if err != nil {
		t.Fatalf("CloneChain: %v", err)
	}
	return synth
}

// TestCertCache_HotMapServesWithoutDisk verifies get() serves a repeat
// lookup from the in-memory hot map populated by put() — proven by
// deleting the on-disk file out from under it and confirming get() still
// hits.
func TestCertCache_HotMapServesWithoutDisk(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	chain := cachableChain(t, ca, ck, fx)
	id := cache.IDFor(realChain)

	if err := cache.put(ctx, id, chain); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := os.Remove(fsPath(dir, certKey(id))); err != nil {
		t.Fatalf("remove on-disk file: %v", err)
	}

	got, ok, source, err := cache.get(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ok {
		t.Fatalf("get() missed after put() even with the on-disk file deliberately removed — hot map isn't serving")
	}
	if source != "hotmap" {
		t.Errorf("source = %q, want hotmap", source)
	}
	if !got[0].Equal(chain[0]) {
		t.Fatalf("get() from hot map returned a different leaf than what was put")
	}
}

// TestCertCache_FlushClearsHotMap verifies Flush() evicts the in-memory
// hot map too, not just the on-disk files — otherwise DELETE /cache would
// silently keep serving pre-flush certs from memory.
func TestCertCache_FlushClearsHotMap(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	chain := cachableChain(t, ca, ck, fx)
	id := cache.IDFor(realChain)
	if err := cache.put(ctx, id, chain); err != nil {
		t.Fatalf("put: %v", err)
	}

	if err := cache.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if _, ok, _, err := cache.get(ctx, id); err != nil || ok {
		t.Fatalf("get() after Flush = ok=%v, err=%v; want a clean miss (hot map not cleared)", ok, err)
	}
}

// TestCertCache_VerifyOnHitRejectsChainNotSignedByCurrentRoot verifies
// "verify on hit": a chain that doesn't actually chain to the CertCache's
// current root (a stale entry from a since-changed CA/clusterKey, or
// corruption) is treated as a miss, not served.
func TestCertCache_VerifyOnHitRejectsChainNotSignedByCurrentRoot(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	otherCA, err := LoadOrGenerateCA(context.Background(), testPosixStorage(t, t.TempDir()), ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (other): %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	// Signed by a DIFFERENT root than the cache's own ca — same clusterKey,
	// so the leaf key still re-derives and matches SPKI, but the chain
	// link to ca.Cert must fail.
	staleChain := cachableChain(t, otherCA, ck, fx)
	id := cache.IDFor(realChain)

	if err := cache.put(ctx, id, staleChain); err != nil {
		t.Fatalf("put: %v", err)
	}

	if _, ok, _, err := cache.get(ctx, id); err != nil || ok {
		t.Fatalf("get() = ok=%v, err=%v; want a clean miss (chain doesn't verify against the current root)", ok, err)
	}
}

// TestCertCache_VerifyOnHitRejectsWrongClusterKey covers the other half of
// the "verify on hit" mismatch: a cached chain whose derived leaf key no
// longer matches the cert's SPKI (a clusterKey change) must also be
// treated as a miss, not just a chain-doesn't-verify-to-root mismatch
// (TestCertCache_VerifyOnHitRejectsChainNotSignedByCurrentRoot).
func TestCertCache_VerifyOnHitRejectsWrongClusterKey(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	// Cloned with a DIFFERENT clusterKey than the cache was constructed
	// with — same ca, so the chain-to-root link is fine, but the leaf's
	// derived key (from the cache's own clusterKey) won't match this
	// chain's actual SPKI.
	otherCK := append([]byte(nil), ck...)
	otherCK[0] ^= 0xFF
	chain := cachableChain(t, ca, otherCK, fx)
	id := cache.IDFor(realChain)

	if err := cache.put(ctx, id, chain); err != nil {
		t.Fatalf("put: %v", err)
	}

	if _, ok, _, err := cache.get(ctx, id); err != nil || ok {
		t.Fatalf("get() = ok=%v, err=%v; want a clean miss (re-derived key doesn't match cached SPKI)", ok, err)
	}
}

// TestCertCache_GetServesFromStorageAfterHotMapEviction covers the "real"
// storage-hit branch of get() — as opposed to every other get() test,
// which (via put()) always populates the hot map first and so never
// actually exercises the disk-read/decode/verify path on a hit.
func TestCertCache_GetServesFromStorageAfterHotMapEviction(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	chain := cachableChain(t, ca, ck, fx)
	id := cache.IDFor(realChain)
	if err := cache.put(ctx, id, chain); err != nil {
		t.Fatalf("put: %v", err)
	}

	cache.mu.Lock()
	delete(cache.hot, id)
	cache.mu.Unlock()

	got, ok, source, err := cache.get(ctx, id)
	if err != nil || !ok {
		t.Fatalf("get() after hot-map eviction = ok=%v, err=%v; want a clean storage hit", ok, err)
	}
	if source != "storage" {
		t.Errorf("source = %q, want storage", source)
	}
	if !got[0].Equal(chain[0]) {
		t.Fatalf("get() from storage returned a different leaf than what was put")
	}

	cache.mu.RLock()
	_, reHot := cache.hot[id]
	cache.mu.RUnlock()
	if !reHot {
		t.Fatalf("a storage hit must repopulate the hot map for the next lookup")
	}
}

// TestCertCache_GetStorageReadError covers get()'s error path when
// Storage.Get fails for a reason OTHER than ErrNotExist — that must
// propagate as an error, not be silently folded into an ordinary miss.
func TestCertCache_GetStorageReadError(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	fx := buildRealFixture(t, nil)
	id := NewCertCache(real, ck, ca).IDFor([]*x509.Certificate{fx.leaf, fx.int})

	boom := errors.New("boom: read failed")
	st := &stubStorage{Storage: real, getErr: boom, getErrKey: certKey(id)}
	cache := NewCertCache(st, ck, ca)

	if _, ok, _, err := cache.get(ctx, id); ok || !errors.Is(err, boom) {
		t.Fatalf("get() = ok=%v, err=%v; want ok=false and an error wrapping %v", ok, err, boom)
	}
}

// TestCertCache_GetDecodeError covers get()'s PKCS#12 decode-failure
// branch: a certs/ entry that isn't valid PKCS#12 (corruption, or a
// stale format from a since-changed cloneFormatVersion landing at the
// same key by coincidence) must surface as an error, not a silent miss
// that would mask real corruption as an ordinary cold cache.
func TestCertCache_GetDecodeError(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	id := cache.IDFor([]*x509.Certificate{fx.leaf, fx.int})
	if err := st.Put(ctx, certKey(id), []byte("not a valid pkcs12 trust store")); err != nil {
		t.Fatalf("seed corrupt entry: %v", err)
	}

	_, ok, _, err := cache.get(ctx, id)
	if ok || err == nil {
		t.Fatalf("get() over corrupted data = ok=%v, err=%v; want a decode error", ok, err)
	}
	if !strings.Contains(err.Error(), "cert: cache: decode") {
		t.Fatalf("err = %q, want it to mention decode", err.Error())
	}
}

// TestCertCache_GetOrderError covers get()'s orderChainLeafFirst-failure
// branch: a syntactically valid PKCS#12 trust store whose certs don't
// actually form one connected chain (here: a real leaf+intermediate plus
// an unrelated third root) must surface as an error.
func TestCertCache_GetOrderError(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	fx := buildRealFixture(t, nil)
	malformed := []*x509.Certificate{fx.leaf, fx.int, selfSignedCert(t, "Unrelated Stray Root")}
	entries := make([]pkcs12.TrustStoreEntry, len(malformed))
	for i, c := range malformed {
		entries[i] = pkcs12.TrustStoreEntry{Cert: c, FriendlyName: fmt.Sprintf("%d", i)}
	}
	data, err := pkcs12.Modern.EncodeTrustStoreEntries(entries, cache.password)
	if err != nil {
		t.Fatalf("EncodeTrustStoreEntries: %v", err)
	}
	id := cache.IDFor([]*x509.Certificate{fx.leaf, fx.int})
	if err := st.Put(ctx, certKey(id), data); err != nil {
		t.Fatalf("seed malformed entry: %v", err)
	}

	_, ok, _, err := cache.get(ctx, id)
	if ok || err == nil {
		t.Fatalf("get() over an unchainable trust store = ok=%v, err=%v; want an ordering error", ok, err)
	}
	if !strings.Contains(err.Error(), "chain has") {
		t.Fatalf("err = %q, want it to mention the leaf-ordering failure", err.Error())
	}
}

// TestCertCache_CountStorageError covers Count()'s error path: the GET
// /stats endpoint must see a real error rather than a misleading zero
// when the backend can't be listed.
func TestCertCache_CountStorageError(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	boom := errors.New("boom: list failed")
	cache := NewCertCache(&stubStorage{Storage: real, listErr: boom}, ck, ca)

	if _, err := cache.Count(ctx); !errors.Is(err, boom) {
		t.Fatalf("Count() err = %v, want it to wrap %v", err, boom)
	}
}

// TestCertCache_FlushStorageError covers Flush()'s error path: the
// DELETE /cache endpoint must report failure rather than claim success
// when the underlying wipe didn't happen.
func TestCertCache_FlushStorageError(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	boom := errors.New("boom: delete-prefix failed")
	cache := NewCertCache(&stubStorage{Storage: real, deletePrefixErr: boom}, ck, ca)

	err = cache.Flush(ctx)
	if !errors.Is(err, boom) {
		t.Fatalf("Flush() err = %v, want it to wrap %v", err, boom)
	}
	if !strings.Contains(err.Error(), "cert: cache: flush") {
		t.Fatalf("err = %q, want it to mention flush", err.Error())
	}
}

// TestCertCache_PutStorageWriteError covers put()'s error path, and the
// invariant that a failed disk write must NOT populate the hot map —
// otherwise a node would serve a "cached" chain from memory that was
// never actually durable, and a restart (or another node reading the
// same key) would see it was never written at all.
func TestCertCache_PutStorageWriteError(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	boom := errors.New("boom: write failed")
	cache := NewCertCache(&stubStorage{Storage: real, putErr: boom}, ck, ca)

	fx := buildRealFixture(t, nil)
	chain := cachableChain(t, ca, ck, fx)
	id := cache.IDFor([]*x509.Certificate{fx.leaf, fx.int})

	err = cache.put(ctx, id, chain)
	if !errors.Is(err, boom) {
		t.Fatalf("put() err = %v, want it to wrap %v", err, boom)
	}
	cache.mu.RLock()
	_, inHot := cache.hot[id]
	cache.mu.RUnlock()
	if inHot {
		t.Fatalf("put() populated the hot map despite a failed disk write")
	}
}

// TestCertCache_EnsureLinksNoLinkerNoOp covers ensureLinks' no-op branch
// for a Storage backend that doesn't implement the optional Linker
// capability (e.g. an S3-style backend) — it must succeed without error,
// simply skipping the operator names/ index.
func TestCertCache_EnsureLinksNoLinkerNoOp(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(noLinkerStorage{Storage: real}, ck, ca)

	fx := buildRealFixture(t, nil)
	if err := cache.ensureLinks(ctx, "some-id", fx.leaf); err != nil {
		t.Fatalf("ensureLinks on a non-Linker backend should no-op, got: %v", err)
	}
}

// TestCertCache_EnsureLinksSymlinkError covers ensureLinks'/symlink's
// error-wrapping branch when the backend's Linker.Symlink call itself
// fails.
func TestCertCache_EnsureLinksSymlinkError(t *testing.T) {
	dir := t.TempDir()
	real := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, real, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	boom := errors.New("boom: symlink failed")
	cache := NewCertCache(failSymlinkStorage{Storage: real, err: boom}, ck, ca)

	fx := buildRealFixture(t, nil)
	err = cache.ensureLinks(ctx, "some-id", fx.leaf)
	if !errors.Is(err, boom) {
		t.Fatalf("ensureLinks() err = %v, want it to wrap %v", err, boom)
	}
	if !strings.Contains(err.Error(), "cert: cache: symlink") {
		t.Fatalf("err = %q, want it to mention symlink", err.Error())
	}
}

// TestCertCache_VerifyEmptyChain covers verify()'s defensive empty-chain
// guard directly — get() can't reach it today (a hot-map or decoded
// storage entry is never an empty slice), but verify() is a standalone
// method and must still fail closed if ever called with one.
func TestCertCache_VerifyEmptyChain(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ca, err := LoadOrGenerateCA(context.Background(), st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	cache := NewCertCache(st, ck, ca)

	if cache.verify(nil) {
		t.Fatalf("verify(nil) = true, want false for an empty chain")
	}
}

// TestCertCache_LoggerCoversHitFlushAndVerifyFailurePaths drives
// WithCacheLogger through every branch it gates: a hot-map hit (Debug),
// a hot-map verify-on-hit failure (Warn), a storage verify-on-hit
// failure (Warn), and Flush (Info) — the default (nil logger, used by
// every other test in this file) skips all four intentionally, per
// WithCacheLogger's doc comment.
func TestCertCache_LoggerCoversHitFlushAndVerifyFailurePaths(t *testing.T) {
	dir := t.TempDir()
	st := testPosixStorage(t, dir)
	ck := testClusterKey()
	ctx := context.Background()
	ca, err := LoadOrGenerateCA(ctx, st, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cache := NewCertCache(st, ck, ca, WithCacheLogger(log))

	fx := buildRealFixture(t, nil)
	realChain := []*x509.Certificate{fx.leaf, fx.int}
	goodChain := cachableChain(t, ca, ck, fx)
	goodID := cache.IDFor(realChain)
	if err := cache.put(ctx, goodID, goodChain); err != nil {
		t.Fatalf("put (good): %v", err)
	}
	if _, ok, source, err := cache.get(ctx, goodID); err != nil || !ok || source != "hotmap" {
		t.Fatalf("get (good, hotmap) = ok=%v source=%q err=%v", ok, source, err)
	}
	if !strings.Contains(buf.String(), "cert cache hit") {
		t.Fatalf("logger missing hot-map hit line; got:\n%s", buf.String())
	}

	otherCK := append([]byte(nil), ck...)
	otherCK[0] ^= 0xFF
	badChain := cachableChain(t, ca, otherCK, fx)
	const badID = "00000000-0000-0000-0000-000000000001"
	if err := cache.put(ctx, badID, badChain); err != nil {
		t.Fatalf("put (bad): %v", err)
	}

	buf.Reset()
	if _, ok, _, err := cache.get(ctx, badID); err != nil || ok {
		t.Fatalf("get (bad, hot-map verify) = ok=%v err=%v; want a clean miss", ok, err)
	}
	if !strings.Contains(buf.String(), "hot-map entry failed verify-on-hit") {
		t.Fatalf("logger missing hot-map verify-fail warning; got:\n%s", buf.String())
	}

	// Evict from the hot map (on-disk copy stays) so the next get()
	// re-decodes from storage and re-runs verify-on-hit there instead.
	cache.mu.Lock()
	delete(cache.hot, badID)
	cache.mu.Unlock()

	buf.Reset()
	if _, ok, _, err := cache.get(ctx, badID); err != nil || ok {
		t.Fatalf("get (bad, storage verify) = ok=%v err=%v; want a clean miss", ok, err)
	}
	if !strings.Contains(buf.String(), "storage entry failed verify-on-hit") {
		t.Fatalf("logger missing storage verify-fail warning; got:\n%s", buf.String())
	}

	buf.Reset()
	if err := cache.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !strings.Contains(buf.String(), "cert cache flushed") {
		t.Fatalf("logger missing flush line; got:\n%s", buf.String())
	}
}

// TestOrderChainLeafFirst_EmptyChain covers the empty-input guard.
func TestOrderChainLeafFirst_EmptyChain(t *testing.T) {
	if _, err := orderChainLeafFirst(nil); err == nil {
		t.Fatalf("orderChainLeafFirst(nil) = nil error, want an error")
	}
}

// TestOrderChainLeafFirst_NoUniqueLeaf covers the "every subject is also
// an issuer" guard: a single self-signed cert's RawIssuer equals its own
// RawSubject, so it disqualifies itself as a leaf and none remains.
func TestOrderChainLeafFirst_NoUniqueLeaf(t *testing.T) {
	fx := buildRealFixture(t, nil)
	_, err := orderChainLeafFirst([]*x509.Certificate{fx.root})
	if err == nil {
		t.Fatalf("orderChainLeafFirst(self-signed root) = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "no unique leaf") {
		t.Fatalf("err = %q, want it to mention no unique leaf", err.Error())
	}
}

// TestOrderChainLeafFirst_LengthMismatch covers the "chain has N certs
// but only M chain from the leaf" guard: a leaf+intermediate pair with
// an unrelated third root has a unique leaf, but walking from it never
// reaches the stray cert, so the reconstructed chain comes up short.
func TestOrderChainLeafFirst_LengthMismatch(t *testing.T) {
	fx := buildRealFixture(t, nil)
	_, err := orderChainLeafFirst([]*x509.Certificate{fx.leaf, fx.int, selfSignedCert(t, "Unrelated Stray Root")})
	if err == nil {
		t.Fatalf("orderChainLeafFirst(disconnected chain) = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "chain has") {
		t.Fatalf("err = %q, want it to mention the length mismatch", err.Error())
	}
}

package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

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

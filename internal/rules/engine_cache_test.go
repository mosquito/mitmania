package rules

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"mitmania/internal/storage"
)

// countingStorage counts Stat calls per key — used to prove the cache TTL
// actually skips Storage.Stat within its window, not just coincidentally
// returns the same result each time.
type countingStorage struct {
	storage.Storage
	mu    sync.Mutex
	stats map[string]int
}

func newCountingStorage(base storage.Storage) *countingStorage {
	return &countingStorage{Storage: base, stats: map[string]int{}}
}

func (c *countingStorage) Stat(ctx context.Context, key string) (storage.Version, error) {
	c.mu.Lock()
	c.stats[key]++
	c.mu.Unlock()
	return c.Storage.Stat(ctx, key)
}

func (c *countingStorage) statCount(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats[key]
}

// TestRuleEngine_CacheTTL_SkipsStatWithinWindow proves WithCacheTTL isn't
// just "usually returns the cached result" — it actually skips calling
// Storage.Stat at all for a second Lookup inside the TTL window.
func TestRuleEngine_CacheTTL_SkipsStatWithinWindow(t *testing.T) {
	counting := newCountingStorage(testStorage(t, t.TempDir()))
	store := NewRuleStore(counting)
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.1")
	// uuid spelled out explicitly, like newRuleEngineErrorHandler in
	// internal/proxy's tests: an omitted uuid would trigger lookupIP's own
	// mint-and-restat Stat call, throwing off this test's count.
	if err := store.Save(ctx, client, []byte(`{"uuid":"stable","http":[]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store, WithCacheTTL(time.Hour))
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}
	if got := counting.statCount(keyFor(client)); got != 1 {
		t.Fatalf("Storage.Stat called %d times across two Lookups within the TTL window, want 1", got)
	}
}

// TestRuleEngine_CacheTTL_MasksChangeWithinWindow proves the TTL window is
// a real cache, not just a fast path: an on-disk change made inside the
// window is not visible until the window elapses.
func TestRuleEngine_CacheTTL_MasksChangeWithinWindow(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.2")
	if err := store.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store, WithCacheTTL(time.Hour))
	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs1 != rs2 || len(rs2.rules) != 0 {
		t.Fatalf("Lookup within the TTL window picked up an on-disk change instead of serving cache: rules len = %d, want 0", len(rs2.rules))
	}
}

// TestRuleEngine_CacheTTL_ExpiresAndReconfirms proves the window is
// bounded: once it elapses, the next Lookup reconfirms against Storage and
// picks up a change made during the window.
func TestRuleEngine_CacheTTL_ExpiresAndReconfirms(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.3")
	if err := store.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store, WithCacheTTL(20*time.Millisecond))
	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs1.rules) != 0 {
		t.Fatalf("initial rules len = %d, want 0", len(rs1.rules))
	}

	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)

	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs2.rules) != 1 {
		t.Fatalf("rules len after TTL expiry = %d, want 1 (picked up the on-disk change)", len(rs2.rules))
	}
}

// TestRuleEngine_CacheTTL_UnchangedVersionProlongsWindow proves the TTL
// window slides forward on every reconfirm: once the original window
// elapses, a Lookup that finds the version still unchanged resets
// checkedAt, so a later Lookup — even though more total time has passed
// than one raw TTL period since the very first Lookup — stays inside the
// (now prolonged) window and skips Storage.Stat again.
func TestRuleEngine_CacheTTL_UnchangedVersionProlongsWindow(t *testing.T) {
	counting := newCountingStorage(testStorage(t, t.TempDir()))
	store := NewRuleStore(counting)
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.8")
	if err := store.Save(ctx, client, []byte(`{"uuid":"stable","http":[]}`)); err != nil {
		t.Fatal(err)
	}

	const ttl = 20 * time.Millisecond
	engine := NewRuleEngine(store, WithCacheTTL(ttl))
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}
	if got := counting.statCount(keyFor(client)); got != 1 {
		t.Fatalf("Stat calls after first Lookup = %d, want 1", got)
	}

	// Past the original window: this Lookup must re-Stat, find the
	// version unchanged, and reset checkedAt.
	time.Sleep(ttl + 10*time.Millisecond)
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}
	if got := counting.statCount(keyFor(client)); got != 2 {
		t.Fatalf("Stat calls after window expiry = %d, want 2 (reconfirmed)", got)
	}

	// Within the PROLONGED window (measured from the reconfirm above, not
	// the original Lookup) despite total elapsed time since the first
	// Lookup already exceeding one raw TTL period.
	time.Sleep(ttl / 2)
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}
	if got := counting.statCount(keyFor(client)); got != 2 {
		t.Fatalf("Stat calls after prolonged window = %d, want still 2 (no re-Stat — window was extended by the unchanged-version reconfirm)", got)
	}
}

// TestRuleEngine_StaleFallback_ClientServedOnStorageError verifies the
// core resilience claim: once cached (with caching enabled), a client's
// RuleSet keeps being served even if Storage.Stat starts failing.
func TestRuleEngine_StaleFallback_ClientServedOnStorageError(t *testing.T) {
	base := testStorage(t, t.TempDir())
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.4")
	if err := base.Put(ctx, keyFor(client), []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}

	fs := &faultyStorage{Storage: base}
	store := NewRuleStore(fs)
	engine := NewRuleEngine(store, WithCacheTTL(time.Millisecond))

	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs1.rules) != 1 {
		t.Fatalf("initial rules len = %d, want 1", len(rs1.rules))
	}

	time.Sleep(5 * time.Millisecond) // let the TTL window elapse so the next Lookup actually re-Stats
	fs.failStat = map[string]error{keyFor(client): errBoom}

	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: expected stale cache to be served despite Storage.Stat failing, got error: %v", err)
	}
	if rs2 != rs1 {
		t.Fatalf("stale fallback did not return the previously cached RuleSet")
	}
}

// TestRuleEngine_StaleFallback_DefaultTableServedOnStorageError is the
// rules/default counterpart: a client resolving via the default table
// keeps being served its last-known-good bucket if Storage.StatDefault
// starts failing.
func TestRuleEngine_StaleFallback_DefaultTableServedOnStorageError(t *testing.T) {
	base := testStorage(t, t.TempDir())
	ctx := context.Background()
	if err := base.Put(ctx, defaultKey, []byte(`{"0.0.0.0/0":{"uuid":"u","http":[{"match":{}}]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}

	fs := &faultyStorage{Storage: base}
	store := NewRuleStore(fs)
	engine := NewRuleEngine(store, WithCacheTTL(time.Millisecond))
	client := netip.MustParseAddr("203.0.113.90")

	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs1.rules) != 1 {
		t.Fatalf("initial rules len = %d, want 1", len(rs1.rules))
	}

	time.Sleep(5 * time.Millisecond)
	fs.failStat = map[string]error{defaultKey: errBoom}

	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: expected stale default table to be served despite Storage.StatDefault failing, got error: %v", err)
	}
	if rs2 != rs1 {
		t.Fatalf("stale fallback did not return the previously resolved default-table RuleSet")
	}
}

// TestRuleEngine_StaleFallback_DisabledWhenCacheTTLZero locks in the
// original fail-closed contract for the default (and explicitly
// unconfigured) case: with no WithCacheTTL, a Storage error always
// propagates, even though an in-memory cache entry happens to exist from
// an earlier successful Lookup. Caching off must mean off, not merely "no
// TTL-skip but stale-serving still happens."
func TestRuleEngine_StaleFallback_DisabledWhenCacheTTLZero(t *testing.T) {
	base := testStorage(t, t.TempDir())
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.5")
	if err := base.Put(ctx, keyFor(client), []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}

	fs := &faultyStorage{Storage: base}
	store := NewRuleStore(fs)
	engine := NewRuleEngine(store) // no WithCacheTTL: caching disabled

	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatal(err)
	}

	fs.failStat = map[string]error{keyFor(client): errBoom}
	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("Lookup: expected a Storage error to propagate with caching disabled, got a stale result instead")
	}
}

// TestRuleEngine_LookupIP_IdenticalContentSkipsRecompile is the
// per-client counterpart of
// TestRuleEngine_Lookup_DefaultTableIdenticalContentSkipsRecompile: a
// byte-identical re-save still bumps storage.Version but is recognized as
// a no-op and reuses the old compiled RuleSet, while a genuine content
// edit — even with the uuid left unchanged — is picked up immediately.
func TestRuleEngine_LookupIP_IdenticalContentSkipsRecompile(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.5.6")
	body := []byte(`{"uuid":"stable","http":[]}`)
	if err := store.Save(ctx, client, body); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs1.rules) != 0 {
		t.Fatalf("initial rules len = %d, want 0", len(rs1.rules))
	}

	time.Sleep(2 * time.Millisecond) // guarantee PosixStorage's mtime-based Version actually moves
	if err := store.Save(ctx, client, body); err != nil {
		t.Fatal(err)
	}
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs1 != rs2 {
		t.Fatalf("byte-identical re-save returned a freshly compiled RuleSet instead of reusing the old one")
	}

	// A real content edit, even with the uuid left unchanged, must be
	// picked up — unlike a uuid-only comparison, content hashing can't
	// mask this.
	if err := store.Save(ctx, client, []byte(`{"uuid":"stable","http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rs3, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs3.rules) != 1 {
		t.Fatalf("rules len after same-uuid content edit = %d, want 1 (content hashing must not mask a real edit)", len(rs3.rules))
	}
}

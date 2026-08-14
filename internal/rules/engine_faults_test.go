package rules

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"mitmania/internal/storage"
)

// errBoom is a generic non-ErrNotExist Storage failure — distinct from a
// missing key so RuleStore's ErrNotExist-to-"absent" translation doesn't
// swallow it.
var errBoom = errors.New("boom: injected storage failure")

// faultyStorage wraps a real storage.Storage and forces specific keys'
// Stat/Get/Put calls to fail, so tests can reach RuleEngine's Storage
// error-propagation branches (Stat/Get/Put all succeed unconditionally on
// PosixStorage in these tests otherwise, and RuleEngine has no interface
// seam to reach them any other way).
type faultyStorage struct {
	storage.Storage
	failStat map[string]error
	failGet  map[string]error
	failPut  map[string]error
}

func (f *faultyStorage) Stat(ctx context.Context, key string) (storage.Version, error) {
	if err, ok := f.failStat[key]; ok {
		return "", err
	}
	return f.Storage.Stat(ctx, key)
}

func (f *faultyStorage) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	if err, ok := f.failGet[key]; ok {
		return nil, "", err
	}
	return f.Storage.Get(ctx, key)
}

func (f *faultyStorage) Put(ctx context.Context, key string, data []byte) error {
	if err, ok := f.failPut[key]; ok {
		return err
	}
	return f.Storage.Put(ctx, key, data)
}

// TestRuleEngine_Lookup_ClientStatErrorPropagates verifies a Storage
// failure on the per-client file's Stat (not just ErrNotExist) surfaces
// as a Lookup error rather than being mistaken for "no override file".
func TestRuleEngine_Lookup_ClientStatErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	client := netip.MustParseAddr("10.0.2.1")
	fs := &faultyStorage{Storage: base, failStat: map[string]error{keyFor(client): errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	if _, err := engine.Lookup(context.Background(), client); err == nil {
		t.Fatalf("Lookup: expected error from Storage.Stat failure, got nil")
	}
}

// TestRuleEngine_Lookup_DefaultTableStatErrorPropagates verifies a
// Storage failure statting rules/default surfaces as a Lookup error for a
// client with no per-client override — the only fallback available to it.
func TestRuleEngine_Lookup_DefaultTableStatErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	fs := &faultyStorage{Storage: base, failStat: map[string]error{defaultKey: errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	client := netip.MustParseAddr("10.0.2.2")
	if _, err := engine.Lookup(context.Background(), client); err == nil {
		t.Fatalf("Lookup: expected error from rules/default Stat failure, got nil")
	}
}

// TestRuleEngine_ResolveEgress_DefaultTableErrorPropagates verifies a
// per-client file that omits "egress" (falling back to rules/default for
// egress policy per resolveEgress's contract) fails the whole Lookup, not
// just the egress half, when that fallback lookup errors — an override
// file must not silently end up with no egress policy at all.
func TestRuleEngine_ResolveEgress_DefaultTableErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.2.3")
	if err := base.Put(ctx, keyFor(client), []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failStat: map[string]error{defaultKey: errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("Lookup: expected error from resolveEgress's rules/default fallback failing")
	}
}

// TestRuleEngine_LookupDefaultTable_GetErrorPropagates verifies a Storage
// failure reading rules/default's content (Stat succeeds, Get doesn't)
// surfaces as a Lookup error rather than an empty/partial table.
func TestRuleEngine_LookupDefaultTable_GetErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	if err := base.Put(ctx, defaultKey, []byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failGet: map[string]error{defaultKey: errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	client := netip.MustParseAddr("10.0.2.4")
	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("Lookup: expected error from rules/default Get failure, got nil")
	}
}

// TestRuleEngine_MintPersistFailure_StillReturnsMintedUUID verifies the
// documented best-effort contract: a failed persist of a newly-minted
// per-client uuid doesn't fail the Lookup that triggered it — the caller
// still gets a usable RuleSet with the minted uuid, and the next Lookup
// (once Storage recovers) simply re-mints/re-persists.
func TestRuleEngine_MintPersistFailure_StillReturnsMintedUUID(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.2.5")
	if err := base.Put(ctx, keyFor(client), []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failPut: map[string]error{keyFor(client): errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rs.UUID() == "" {
		t.Fatalf("UUID() empty — a minted uuid should still be returned even when persisting it failed")
	}
}

// TestRuleEngine_DefaultMintPersistFailure_StillReturnsCompiledTable is
// the rules/default counterpart of
// TestRuleEngine_MintPersistFailure_StillReturnsMintedUUID: a failed
// persist of newly-minted bucket uuids doesn't fail the Lookup either.
func TestRuleEngine_DefaultMintPersistFailure_StillReturnsCompiledTable(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	if err := base.Put(ctx, defaultKey, []byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failPut: map[string]error{defaultKey: errBoom}}

	engine := NewRuleEngine(NewRuleStore(fs))
	client := netip.MustParseAddr("203.0.113.60")
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, _, matched := rs.LookupConn(ConnInput{Host: "anything", Port: "443", Proto: "https"}); matched {
		t.Fatalf("expected the empty compiled bucket to still match nothing, despite the persist failure")
	}
}

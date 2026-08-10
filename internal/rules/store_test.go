package rules

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"mitmania/internal/storage"
)

func testStorage(t *testing.T, dir string) storage.Storage {
	t.Helper()
	st, err := storage.NewPosixStorage(dir)
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	return st
}

func TestRuleStore_LoadMissingIsEmpty(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	rf, err := store.Load(context.Background(), netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rf.HTTP) != 0 {
		t.Fatalf("HTTP = %v, want empty", rf.HTTP)
	}
}

func TestRuleStore_SaveLoadRoundTrip(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.2")
	doc := []byte(`{"http":[{"match":{"host":"x"}}]}`)
	if err := store.Save(ctx, client, doc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	rf, err := store.Load(ctx, client)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rf.HTTP) != 1 || rf.HTTP[0].Match.Host != "x" {
		t.Fatalf("Load = %+v", rf)
	}

	raw, err := store.LoadRaw(ctx, client)
	if err != nil {
		t.Fatalf("LoadRaw: %v", err)
	}
	if string(raw) != string(doc) {
		t.Fatalf("LoadRaw = %q, want %q", raw, doc)
	}
}

func TestRuleStore_FileNamedBySHA1OfClientIP(t *testing.T) {
	dir := t.TempDir()
	store := NewRuleStore(testStorage(t, dir))
	client := netip.MustParseAddr("192.168.1.1")
	if err := store.Save(context.Background(), client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}

	want := keyFor(client)
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(want))); err != nil {
		t.Fatalf("expected file %s: %v", want, err)
	}
}

func TestRuleStore_DifferentIPsDifferentFiles(t *testing.T) {
	a := keyFor(netip.MustParseAddr("10.0.0.1"))
	b := keyFor(netip.MustParseAddr("10.0.0.2"))
	if a == b {
		t.Fatalf("different IPs produced the same filename: %s", a)
	}
}

func TestRuleStore_LoadRaw_Missing(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	raw, err := store.LoadRaw(context.Background(), netip.MustParseAddr("10.0.0.9"))
	if err != nil {
		t.Fatalf("LoadRaw: %v", err)
	}
	if raw != nil {
		t.Fatalf("LoadRaw = %v, want nil", raw)
	}
}

func TestRuleStore_DeleteRemovesFile(t *testing.T) {
	dir := t.TempDir()
	store := NewRuleStore(testStorage(t, dir))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.3")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(keyFor(client)))); err != nil {
		t.Fatalf("expected file to exist before Delete: %v", err)
	}

	if err := store.Delete(ctx, client); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(keyFor(client)))); !os.IsNotExist(err) {
		t.Fatalf("file survived Delete (stat err = %v)", err)
	}

	raw, err := store.LoadRaw(ctx, client)
	if err != nil {
		t.Fatalf("LoadRaw after Delete: %v", err)
	}
	if raw != nil {
		t.Fatalf("LoadRaw after Delete = %v, want nil", raw)
	}
}

func TestRuleStore_DeleteMissingIsNotAnError(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	if err := store.Delete(context.Background(), netip.MustParseAddr("10.0.0.4")); err != nil {
		t.Fatalf("Delete of a nonexistent client's rules should be a no-op, got: %v", err)
	}
}

func TestRuleStore_EnsureDefault_SeedsOnlyWhenAbsent(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()

	if err := store.EnsureDefault(ctx); err != nil {
		t.Fatalf("EnsureDefault: %v", err)
	}
	raw, err := store.LoadRawDefault(ctx)
	if err != nil {
		t.Fatalf("LoadRawDefault: %v", err)
	}
	if string(raw) != string(BuiltinDefaultRuleset) {
		t.Fatalf("LoadRawDefault after EnsureDefault = %s, want %s (BuiltinDefaultRuleset)", raw, BuiltinDefaultRuleset)
	}
	if _, _, err := CompileDefaultRuleset(raw); err != nil {
		t.Fatalf("seeded default failed its own coverage check: %v", err)
	}

	// A second call must not overwrite an operator's own table.
	custom := []byte(`{"0.0.0.0/0":{"uuid":"custom","http":[]},"::/0":{"http":[]}}`)
	if err := store.SaveDefault(ctx, custom); err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}
	if err := store.EnsureDefault(ctx); err != nil {
		t.Fatalf("EnsureDefault (second call): %v", err)
	}
	rawAfter, err := store.LoadRawDefault(ctx)
	if err != nil {
		t.Fatalf("LoadRawDefault: %v", err)
	}
	if string(rawAfter) != string(custom) {
		t.Fatalf("EnsureDefault overwrote an existing rules/default: got %s, want %s", rawAfter, custom)
	}
}

func TestRuleStore_DefaultRoundTrip(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()

	if raw, err := store.LoadRawDefault(ctx); err != nil || raw != nil {
		t.Fatalf("LoadRawDefault(missing) = %+v, %v; want nil, nil", raw, err)
	}
	if _, exists, err := store.StatDefault(ctx); err != nil || exists {
		t.Fatalf("StatDefault(missing) = exists=%v, err=%v; want false, nil", exists, err)
	}

	body := []byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`)
	if err := store.SaveDefault(ctx, body); err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}

	rawBytes, err := store.LoadRawDefault(ctx)
	if err != nil || string(rawBytes) != string(body) {
		t.Fatalf("LoadRawDefault = %s, %v; want %s, nil", rawBytes, err, body)
	}

	if _, exists, err := store.StatDefault(ctx); err != nil || !exists {
		t.Fatalf("StatDefault = exists=%v, err=%v; want true, nil", exists, err)
	}
}

package rules

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

// newTestLogger returns a slog.Logger whose output lands in buf, so a
// test can assert on the specific record WithLogger is documented to
// emit (an Info per compile/hot-reload, a Warn per compile failure)
// without depending on slog's internal formatting beyond substring
// containment.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// TestRuleEngine_WithLogger_LogsFirstLoadAndHotReload verifies
// WithLogger's documented behavior for the per-client path: an Info
// record on first compile, tagged "first load", and another tagged
// "hot-reload" once the file changes underneath the cache.
func TestRuleEngine_WithLogger_LogsFirstLoadAndHotReload(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.3.1")
	if err := store.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}

	logger, buf := newTestLogger()
	engine := NewRuleEngine(store, WithLogger(logger))

	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (first): %v", err)
	}
	if !strings.Contains(buf.String(), "first load") {
		t.Fatalf("expected a \"first load\" log record, got: %s", buf.String())
	}

	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (hot-reload): %v", err)
	}
	if !strings.Contains(buf.String(), "hot-reload") {
		t.Fatalf("expected a \"hot-reload\" log record, got: %s", buf.String())
	}
}

// TestRuleEngine_WithLogger_LogsDefaultTableFirstLoadAndHotReload is the
// rules/default counterpart: same "first load"/"hot-reload" reason
// tagging, on the shared default-table compile path instead of a
// per-client one.
func TestRuleEngine_WithLogger_LogsDefaultTableFirstLoadAndHotReload(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.70")
	if err := store.SaveDefault(ctx, []byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}

	logger, buf := newTestLogger()
	engine := NewRuleEngine(store, WithLogger(logger))

	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (first): %v", err)
	}
	if !strings.Contains(buf.String(), "default ruleset compiled") || !strings.Contains(buf.String(), "first load") {
		t.Fatalf("expected a default-ruleset \"first load\" log record, got: %s", buf.String())
	}

	if err := store.SaveDefault(ctx, []byte(`{"0.0.0.0/0":{"http":[{"match":{}}]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup (hot-reload): %v", err)
	}
	if !strings.Contains(buf.String(), "hot-reload") {
		t.Fatalf("expected a default-ruleset \"hot-reload\" log record, got: %s", buf.String())
	}
}

// TestRuleEngine_WithLogger_LogsCompileFailure verifies the documented
// "a Warn record if compilation fails" half of WithLogger's contract.
func TestRuleEngine_WithLogger_LogsCompileFailure(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.3.2")
	if err := store.Save(ctx, client, []byte(`not valid json`)); err != nil {
		t.Fatal(err)
	}

	logger, buf := newTestLogger()
	engine := NewRuleEngine(store, WithLogger(logger))
	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("Lookup: expected a compile error for invalid JSON")
	}
	if !strings.Contains(buf.String(), "rule file compile failed") {
		t.Fatalf("expected a compile-failure Warn record, got: %s", buf.String())
	}
}

// TestRuleEngine_WithLogger_LogsMintPersistFailure verifies the
// mint-then-persist best-effort path (lookupIP) logs its own Warn when
// the persist fails, distinct from a compile failure — Lookup itself
// still succeeds (TestRuleEngine_MintPersistFailure_StillReturnsMintedUUID
// covers that half; this test is only about the log record).
func TestRuleEngine_WithLogger_LogsMintPersistFailure(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.3.3")
	if err := base.Put(ctx, keyFor(client), []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failPut: map[string]error{keyFor(client): errBoom}}

	logger, buf := newTestLogger()
	engine := NewRuleEngine(NewRuleStore(fs), WithLogger(logger))
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(buf.String(), "failed to persist minted uuid") {
		t.Fatalf("expected a mint-persist-failure Warn record, got: %s", buf.String())
	}
}

// TestRuleEngine_WithLogger_LogsDefaultMintPersistFailure is the
// rules/default counterpart of
// TestRuleEngine_WithLogger_LogsMintPersistFailure.
func TestRuleEngine_WithLogger_LogsDefaultMintPersistFailure(t *testing.T) {
	dir := t.TempDir()
	base := testStorage(t, dir)
	ctx := context.Background()
	if err := base.Put(ctx, defaultKey, []byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}
	fs := &faultyStorage{Storage: base, failPut: map[string]error{defaultKey: errBoom}}

	logger, buf := newTestLogger()
	engine := NewRuleEngine(NewRuleStore(fs), WithLogger(logger))
	client := netip.MustParseAddr("203.0.113.71")
	if _, err := engine.Lookup(ctx, client); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !strings.Contains(buf.String(), "failed to persist minted default uuid") {
		t.Fatalf("expected a default mint-persist-failure Warn record, got: %s", buf.String())
	}
}

package rules

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"mitmania/internal/storage"
)

// rulesPrefix is the Storage key prefix for per-client rule files:
// rules/ip/{sha1(clientIP)}.json — hashed rather than the literal address,
// the same non-identity-revealing key convention used elsewhere in the
// codebase (e.g. the leaf-cert cache's name lookups). defaultKey is the
// single blob holding the gapless address/mask-keyed default ruleset:
// rules/default.
const (
	ipPrefix   = "rules/ip/"
	defaultKey = "rules/default"
)

// RuleStore reads/writes per-client rule files and the shared default
// ruleset blob via Storage.
type RuleStore struct {
	storage storage.Storage
}

// NewRuleStore returns a RuleStore backed by store.
func NewRuleStore(store storage.Storage) *RuleStore {
	return &RuleStore{storage: store}
}

func keyFor(client netip.Addr) string {
	sum := sha1.Sum([]byte(client.String()))
	return ipPrefix + hex.EncodeToString(sum[:]) + ".json"
}

// Load reads and parses client's rule file. A missing file isn't an
// error — it's an empty RuleFile, so RuleEngine.Lookup falls through to
// the rules/default table.
func (s *RuleStore) Load(ctx context.Context, client netip.Addr) (RuleFile, error) {
	return s.load(ctx, keyFor(client))
}

func (s *RuleStore) load(ctx context.Context, key string) (RuleFile, error) {
	data, _, err := s.storage.Get(ctx, key)
	if errors.Is(err, storage.ErrNotExist) {
		return RuleFile{}, nil
	}
	if err != nil {
		return RuleFile{}, fmt.Errorf("rules: read %s: %w", key, err)
	}
	var rf RuleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return RuleFile{}, fmt.Errorf("rules: parse %s: %w", key, err)
	}
	return rf, nil
}

// Save atomically writes client's rule file (the control API's
// PUT /rules/{ip}). Save does not itself validate data — callers should Compile it first
// so an invalid rule file is rejected before it's ever persisted.
func (s *RuleStore) Save(ctx context.Context, client netip.Addr, data []byte) error {
	return s.storage.Put(ctx, keyFor(client), data)
}

// Delete removes client's rule file (the control API's DELETE /rules/{ip})
// — revoking its override so the client falls back to the rules/default
// table. Idempotent: deleting an already-absent file is not an error.
func (s *RuleStore) Delete(ctx context.Context, client netip.Addr) error {
	return s.storage.Delete(ctx, keyFor(client))
}

// LoadRaw returns a client's rule file's raw bytes, e.g. for the control
// API's GET /rules to echo back verbatim. Returns (nil, nil) if no file
// exists.
func (s *RuleStore) LoadRaw(ctx context.Context, client netip.Addr) ([]byte, error) {
	return s.loadRaw(ctx, keyFor(client))
}

func (s *RuleStore) loadRaw(ctx context.Context, key string) ([]byte, error) {
	data, _, err := s.storage.Get(ctx, key)
	if errors.Is(err, storage.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", key, err)
	}
	return data, nil
}

// Stat returns client's rule file's freshness fingerprint — a
// storage.Version, cheap to get without reading the file's contents.
// RuleEngine uses it to skip a re-read+recompile when nothing changed.
// exists is false when the file is absent (a zero Version, which —
// being a value no real key's Version will ever equal on first
// appearance — correctly never matches a stale "missing" cache entry
// once a file shows up).
func (s *RuleStore) Stat(ctx context.Context, client netip.Addr) (version storage.Version, exists bool, err error) {
	return s.stat(ctx, keyFor(client))
}

func (s *RuleStore) stat(ctx context.Context, key string) (storage.Version, bool, error) {
	v, err := s.storage.Stat(ctx, key)
	if errors.Is(err, storage.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("rules: stat %s: %w", key, err)
	}
	return v, true, nil
}

// LoadRawDefault returns the rules/default blob's raw bytes, e.g. for the
// control API's GET /rules/default to echo back verbatim. Returns (nil,
// nil) if no blob exists.
func (s *RuleStore) LoadRawDefault(ctx context.Context) ([]byte, error) {
	return s.loadRaw(ctx, defaultKey)
}

// SaveDefault atomically writes the rules/default blob (the control API's
// PUT /rules/default). Like Save, it does not itself validate data —
// callers should run it through CompileDefaultRuleset first so an
// incomplete or otherwise invalid table is rejected before it's ever
// persisted.
func (s *RuleStore) SaveDefault(ctx context.Context, data []byte) error {
	return s.storage.Put(ctx, defaultKey, data)
}

// StatDefault is Stat's rules/default counterpart — RuleEngine's
// hot-reload fingerprint for the one shared blob.
func (s *RuleStore) StatDefault(ctx context.Context) (version storage.Version, exists bool, err error) {
	return s.stat(ctx, defaultKey)
}

// EnsureDefault seeds rules/default with BuiltinDefaultRuleset if no blob
// exists yet — called once at startup, so a fresh cluster with no per-IP
// overrides either still satisfies the "always complete" coverage
// obligation instead of leaving every unconfigured client permanently
// unreachable until an operator PUTs one by hand. Idempotent, and safe
// under concurrent multi-node startup: a Stat-then-Put race is possible
// but harmless: Storage writes in this design are last-write-wins
// everywhere, so whichever node's write lands last still leaves a valid,
// complete table.
func (s *RuleStore) EnsureDefault(ctx context.Context) error {
	_, exists, err := s.StatDefault(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.SaveDefault(ctx, BuiltinDefaultRuleset)
}

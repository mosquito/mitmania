package rules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"mitmania/internal/storage"
	"mitmania/internal/telemetry"
)

// ConnInput is what's known at connection-phase, before any upstream
// dial: SNI/dst host, port, and (for HTTP) whether the connection
// arrived via CONNECT+TLS ("https") or plain absolute-form ("http").
type ConnInput struct {
	Host  string
	Port  string
	Proto string
}

// MsgInput adds what's known once the HTTP/1.1 request has been read.
type MsgInput struct {
	ConnInput
	Path   string
	Method string
	Header http.Header
}

// RuleSet is one client's compiled http[] rule list plus its egress[]
// policy — two independent lists over the same connection.
type RuleSet struct {
	rules     []CompiledRule
	hostIndex *hostCandidateIndex
	egress    []CompiledEgress
	uuid      string
	auth      *CompiledAuth
}

func newRuleSet(rules []CompiledRule, egress []CompiledEgress, uuid string, auth *CompiledAuth) *RuleSet {
	return newRuleSetWithHostIndex(rules, buildHostCandidateIndex(rules), egress, uuid, auth)
}

func newRuleSetWithHostIndex(rules []CompiledRule, hostIndex *hostCandidateIndex, egress []CompiledEgress, uuid string, auth *CompiledAuth) *RuleSet {
	return &RuleSet{
		rules:     rules,
		hostIndex: hostIndex,
		egress:    egress,
		uuid:      uuid,
		auth:      auth,
	}
}

// UUID is this rule file's top-level identity — the proxied client's
// stable identity, operator-assigned or a persisted uuid4 minted
// by Lookup if the file existed but omitted it. Empty for a client with
// no rule file at all (nothing to mint into).
func (rs *RuleSet) UUID() string { return rs.uuid }

// Auth is this rule file's compiled auth.http_proxy block, or nil if the
// file has no "auth" key — the default, meaning source IP alone is
// this client's identity with no credential gate.
func (rs *RuleSet) Auth() *CompiledAuth { return rs.auth }

// HTTPRules exposes rs's compiled http[] chain — for control's PUT-time
// outcall probe, which needs to walk every rule's request[] actions
// regardless of which bucket/file they came from.
func (rs *RuleSet) HTTPRules() []CompiledRule { return rs.rules }

// LookupConn is the connection-phase first-match pass: only
// host/port/proto are visible. matched is false when no rule's
// connection-phase predicate matched at all — the caller then fails
// closed with a 511 rather than letting the connection through. deny is
// true when the matched rule rejects the connection outright (see
// Rule.Connection) — the caller must not dial or attempt TLS termination
// at all in that case; mitm is meaningless (always false) when deny is true.
func (rs *RuleSet) LookupConn(in ConnInput) (mitm bool, deny bool, matched bool) {
	if rs.hostIndex == nil {
		for _, r := range rs.rules {
			if r.connHost.match(in.Host) && r.connPort.match(in.Port) && r.connProto.match(in.Proto) {
				return r.mitm, r.deny, true
			}
		}
		return false, false, false
	}
	var local [32]int
	for _, ruleID := range rs.hostIndex.appendCandidates(in.Host, local[:0]) {
		r := &rs.rules[ruleID]
		if r.connHost.match(in.Host) && r.connPort.match(in.Port) && r.connProto.match(in.Proto) {
			return r.mitm, r.deny, true
		}
	}
	return false, false, false
}

// LookupRequest is the message-phase first-match pass: the single
// rule whose full predicate (host+port+proto+path+method+header) matches
// is the one whose request[]/response[] pipeline runs — exactly one rule,
// no cascading.
func (rs *RuleSet) LookupRequest(in MsgInput) (*CompiledRule, bool) {
	if rs.hostIndex == nil {
		for i := range rs.rules {
			r := &rs.rules[i]
			if r.deny {
				continue // never reaches a message phase to be selected in
			}
			if !r.connHost.match(in.Host) || !r.connPort.match(in.Port) || !r.connProto.match(in.Proto) {
				continue
			}
			if !r.msgPath.match(in.Path) || !r.msgMethod.match(in.Method) {
				continue
			}
			if !matchHeaders(r.msgHeader, in.Header) {
				continue
			}
			return r, true
		}
		return nil, false
	}
	var local [32]int
	for _, ruleID := range rs.hostIndex.appendCandidates(in.Host, local[:0]) {
		r := &rs.rules[ruleID]
		if r.deny {
			continue
		}
		if !r.connHost.match(in.Host) || !r.connPort.match(in.Port) || !r.connProto.match(in.Proto) {
			continue
		}
		if !r.msgPath.match(in.Path) || !r.msgMethod.match(in.Method) {
			continue
		}
		if !matchHeaders(r.msgHeader, in.Header) {
			continue
		}
		return r, true
	}
	return nil, false
}

// LookupEgress is the ordered egress[] firstmatch pass: addr's prefix
// containment, port, and proto (the L7 handler name, e.g. "http" — not
// ConnInput.Proto's http/https transport distinction) against each
// compiled entry in order. matched is false on fall-off-the-end —
// deny-by-omission is the only fail mode, so callers can treat !allow
// the same whether or not matched is true.
func (rs *RuleSet) LookupEgress(addr netip.Addr, port uint16, proto string) (allow bool, matched bool) {
	for _, e := range rs.egress {
		if e.prefix.Contains(addr) && e.port.match(port) && e.proto.match(proto) {
			return e.allow, true
		}
	}
	return false, false
}

func matchHeaders(want map[string]matcher, got http.Header) bool {
	for name, m := range want {
		if !m.match(got.Get(name)) {
			return false
		}
	}
	return true
}

// RuleEngine checks a client's rule blob's storage.Version on every
// Lookup and only re-reads/recompiles when that's changed since the last
// time, reusing the in-memory RuleSet otherwise. There's no explicit
// reload path: a PUT /rules/{ip}, a PUT /rules/default, or a hand-edited
// file simply changes the blob's Version, which the very next Lookup
// notices on its own — no invalidation signal to wire up, no staleness
// beyond the cost of one Storage.Stat per connection.
type RuleEngine struct {
	store *RuleStore

	// log, if set (WithLogger), receives an Info record every time a
	// client's rule file or the default ruleset is (re)compiled — first
	// load or a hot-reload — and a Warn record if compilation fails. nil
	// disables both.
	log *slog.Logger

	// metrics/tracer back the rules.compiles.total/.active_clients/
	// .compile.duration metrics and a "rules.compile" child span —
	// nil-safe, same convention as log. Both only fire on an actual
	// (re)compile, never on Lookup's cached-hit fast path — matching
	// what "compile" means.
	metrics *telemetry.Metrics
	tracer  trace.Tracer

	// cacheTTL bounds how long Lookup/lookupDefaultTable trust an
	// already-resolved cache entry before reconfirming it against
	// Storage — set by WithCacheTTL (wired to --rules-cache-ttl at the
	// application level). Zero, the zero value and NewRuleEngine's own
	// default, means "always reconfirm": the original per-connection
	// Storage.Stat behavior, unchanged for any caller that doesn't
	// opt in. A positive value trades a bounded window of policy
	// staleness for a bounded number of Storage round-trips under load,
	// and — independently of the TTL window — lets a cache entry that's
	// still fresh in memory keep serving if Storage itself becomes
	// unreachable, rather than failing every connection the instant
	// Storage blips. It never masks a genuine compile/validation failure
	// of content Storage did successfully return: that always fails
	// closed (see lookupIP/lookupDefaultTable's Compile error paths).
	cacheTTL time.Duration

	mu sync.Mutex
	// cache holds one entry per client this engine has ever resolved —
	// both clients with an actual rules/ip override (exists: true) and
	// clients confirmed to have none (exists: false, resolved via
	// defaultCache instead) — so neither case costs a Storage.Stat on
	// every single connection once cacheTTL is enabled.
	cache map[netip.Addr]cachedRuleSet
	// defaultCache is the single compiled rules/default table — there's
	// exactly one blob, so one slot, versioned by its own storage.Version
	// independent of any per-client file's.
	defaultCache *cachedDefault
}

// cachedRuleSet is one client's last-resolved override state. checkedAt is
// when this entry was last confirmed against Storage — cacheTTL gates how
// long it's trusted without reconfirming, and it's also what "stale but
// still the last known-good state" falls back to on a Storage error.
type cachedRuleSet struct {
	checkedAt time.Time
	version   storage.Version
	exists    bool // false: confirmed no rules/ip override exists; ruleSet is nil, resolve via the default table instead
	ruleSet   *RuleSet
	// contentHash is a sha256 of the source RuleFile (uuid, http, egress,
	// auth all included) that produced ruleSet — see lookupIP's use of it.
	contentHash [32]byte
}

type cachedDefault struct {
	checkedAt time.Time
	version   storage.Version
	exists    bool
	ruleset   *DefaultRuleset
}

// RuleEngineOption configures NewRuleEngine.
type RuleEngineOption func(*RuleEngine)

// WithLogger enables Lookup's compile/hot-reload logging — nil (the
// default) disables it, same convention as Http1Handler.Logger.
func WithLogger(log *slog.Logger) RuleEngineOption {
	return func(e *RuleEngine) { e.log = log }
}

// WithMetrics enables the rules.compiles.total/.active_clients/
// .compile.duration metrics — nil (the default) leaves them unrecorded.
func WithMetrics(m *telemetry.Metrics) RuleEngineOption {
	return func(e *RuleEngine) { e.metrics = m }
}

// WithTracer enables a "rules.compile" child span per actual (re)compile
// — nil (the default) leaves tracing off.
func WithTracer(t trace.Tracer) RuleEngineOption {
	return func(e *RuleEngine) { e.tracer = t }
}

// WithCacheTTL sets RuleEngine.cacheTTL — see its doc comment. Not calling
// this (or passing 0) preserves NewRuleEngine's original always-reconfirm
// behavior; every existing caller that doesn't pass this option is
// unaffected.
func WithCacheTTL(d time.Duration) RuleEngineOption {
	return func(e *RuleEngine) { e.cacheTTL = d }
}

func NewRuleEngine(store *RuleStore, opts ...RuleEngineOption) *RuleEngine {
	e := &RuleEngine{store: store, cache: map[netip.Addr]cachedRuleSet{}}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Lookup returns client's current RuleSet: its per-client override
// (rules/ip/{sha1(clientIP)}.json) if one exists, else the highest-ranked
// rules/default bucket whose address/mask matches client — DefaultRuleset
// sorts each family's buckets by mask value descending and returns the
// first match, not literal longest-prefix-match, though that ranking
// subsumes prefix containment as a special case — else an empty RuleSet
// if neither is available — every connection then falls through to
// "no match -> 511", the same fail-closed behavior an unconfigured fleet
// has always had.
func (e *RuleEngine) Lookup(ctx context.Context, client netip.Addr) (*RuleSet, error) {
	e.mu.Lock()
	cached, hasCache := e.cache[client]
	e.mu.Unlock()

	if hasCache && e.fresh(cached.checkedAt) {
		return e.resolveClientCache(ctx, client, cached)
	}

	version, exists, err := e.store.Stat(ctx, client)
	if err != nil {
		if e.cacheTTL > 0 && hasCache {
			e.staleFallback("client", client.String(), err)
			return e.resolveClientCache(ctx, client, cached)
		}
		return nil, err
	}

	if hasCache && cached.version == version && cached.exists == exists {
		e.touchClientCache(client, cached)
		return e.resolveClientCache(ctx, client, cached)
	}

	if !exists {
		entry := cachedRuleSet{checkedAt: time.Now(), version: version, exists: false}
		e.mu.Lock()
		e.cache[client] = entry
		e.mu.Unlock()
		return e.resolveClientCache(ctx, client, entry)
	}

	return e.lookupIP(ctx, client, version, cached)
}

// resolveClientCache turns a client cache entry (freshly confirmed or
// served stale) into the RuleSet Lookup returns: the entry's own RuleSet
// for a client with an override, or the default table's match for one
// without.
func (e *RuleEngine) resolveClientCache(ctx context.Context, client netip.Addr, cached cachedRuleSet) (*RuleSet, error) {
	if cached.exists {
		return cached.ruleSet, nil
	}
	def, err := e.lookupDefaultTable(ctx)
	if err != nil {
		return nil, err
	}
	if def != nil {
		if rs, ok := def.Lookup(client); ok {
			return rs, nil
		}
	}
	return &RuleSet{}, nil
}

// touchClientCache refreshes an unchanged entry's checkedAt without
// altering its resolved content — resets the TTL window on a cheap
// version-confirmed hit, the same way lookupIP/lookupDefaultTable do for
// their own cache entries.
func (e *RuleEngine) touchClientCache(client netip.Addr, cached cachedRuleSet) {
	cached.checkedAt = time.Now()
	e.mu.Lock()
	e.cache[client] = cached
	e.mu.Unlock()
}

// fresh reports whether checkedAt is still within cacheTTL — false
// whenever cacheTTL is 0 (disabled), so every Lookup reconfirms against
// Storage, unchanged from the original behavior.
func (e *RuleEngine) fresh(checkedAt time.Time) bool {
	return e.cacheTTL > 0 && time.Since(checkedAt) < e.cacheTTL
}

// staleFallback logs that a Storage error is being masked by serving an
// already-cached entry rather than failing the connection — kind/id name
// which cache ("client"/client's address, or "default") is being served
// stale.
func (e *RuleEngine) staleFallback(kind, id string, err error) {
	if e.log != nil {
		e.log.Warn("rules: storage unavailable, serving last-known-good cached rules", "kind", kind, "id", id, "err", err.Error())
	}
}

// lookupIP (re)compiles client's per-client override file. prevCache is
// Lookup's cache entry for client before this call, if any — used only to
// check whether the freshly loaded file's content is unchanged (see
// compileParsedEntries's doc comment for the identical rules/default
// case): when it is, the whole previously compiled RuleSet is reused
// instead of recompiling.
func (e *RuleEngine) lookupIP(ctx context.Context, client netip.Addr, version storage.Version, prevCache cachedRuleSet) (*RuleSet, error) {
	logID := client.String()

	start := time.Now()
	if e.tracer != nil {
		var span trace.Span
		ctx, span = e.tracer.Start(ctx, "rules.compile", trace.WithAttributes(attribute.String("client", logID)))
		defer span.End()
	}

	rf, err := e.store.Load(ctx, client)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	// A file that exists but omits "uuid" gets one minted and persisted
	// back — best-effort. A persist failure just means this process
	// re-mints (and re-persists) on its next Lookup rather than failing
	// the request; a concurrent racing mint from another node is
	// harmless last-write-wins, same as every other Storage write in
	// this design.
	if rf.UUID == "" {
		rf.UUID = uuid.NewString()
		if data, merr := json.Marshal(rf); merr == nil {
			if serr := e.store.Save(ctx, client, data); serr != nil {
				if e.log != nil {
					e.log.Warn("rules: failed to persist minted uuid", "client", logID, "err", serr.Error())
				}
			} else if newVersion, _, serr2 := e.store.Stat(ctx, client); serr2 == nil {
				// Re-stat after a successful persist so the cache entry
				// written below reflects the file's ACTUAL current
				// version — otherwise the very next Lookup would see
				// this mint's own write as "changed" and needlessly
				// recompile a second time before reaching a stable
				// cache hit.
				version = newVersion
			}
		}
	}

	// A storage.Version bump doesn't always mean this file's own content
	// changed — a redundant re-PUT of identical bytes is enough on some
	// backends. Comparing a hash of the whole loaded RuleFile (uuid,
	// http, egress, auth — everything) against what produced the
	// previously cached RuleSet catches that case (and is computed from
	// content already in hand, not an extra Storage round-trip) without
	// the risk a uuid-only comparison would carry: any real edit, uuid
	// bump or not, changes the hash and forces a real recompile below.
	ruleJSON, err := json.Marshal(rf)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}
	hash := sha256.Sum256(ruleJSON)
	if prevCache.exists && prevCache.ruleSet != nil && hash == prevCache.contentHash {
		e.mu.Lock()
		e.cache[client] = cachedRuleSet{checkedAt: time.Now(), version: version, exists: true, ruleSet: prevCache.ruleSet, contentHash: hash}
		e.mu.Unlock()
		if e.log != nil {
			e.log.Info("rule file unchanged, skipped recompile", "client", logID)
		}
		return prevCache.ruleSet, nil
	}

	auth, err := CompileAuth(rf.Auth)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	compiled, err := Compile(rf)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	egress, err := e.resolveEgress(ctx, client, rf)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}
	rs := newRuleSet(compiled, egress, rf.UUID, auth)

	e.mu.Lock()
	_, wasCached := e.cache[client]
	e.cache[client] = cachedRuleSet{checkedAt: time.Now(), version: version, exists: true, ruleSet: rs, contentHash: hash}
	e.mu.Unlock()

	if e.log != nil {
		reason := "first load"
		if wasCached {
			reason = "hot-reload"
		}
		e.log.Info("rule file compiled", "client", logID, "reason", reason, "http_rules", len(compiled), "egress_rules", len(egress))
	}
	e.metrics.RuleCompile(ctx, "ok", time.Since(start))
	if !wasCached {
		e.metrics.RulesActiveClients(ctx, 1)
	}

	return rs, nil
}

// resolveEgress is a per-client override file's egress[] resolution: its
// own list if "egress" is present (even empty — that's a
// deliberate "match nothing", not an opt-out), otherwise whichever
// rules/default bucket covers client — there is exactly one "default"
// concept in this design, not a separate egress-only fallback, so an
// override file that only wants to customize http[] can still lean on
// the default table for egress by simply omitting the key.
func (e *RuleEngine) resolveEgress(ctx context.Context, client netip.Addr, rf RuleFile) ([]CompiledEgress, error) {
	if rf.Egress != nil {
		return CompileEgress(rf.Egress)
	}
	def, err := e.lookupDefaultTable(ctx)
	if err != nil {
		return nil, err
	}
	if def != nil {
		if rs, ok := def.Lookup(client); ok {
			return rs.egress, nil
		}
	}
	return nil, nil
}

// lookupDefaultTable returns the compiled rules/default table,
// recompiling only when its storage.Version has changed. nil, nil means
// no blob has been saved yet — callers treat that as "nothing to fall
// back to", same as any other coverage gap.
func (e *RuleEngine) lookupDefaultTable(ctx context.Context) (*DefaultRuleset, error) {
	e.mu.Lock()
	cached := e.defaultCache
	e.mu.Unlock()

	if cached != nil && e.fresh(cached.checkedAt) {
		return cached.ruleset, nil
	}

	version, exists, err := e.store.StatDefault(ctx)
	if err != nil {
		if e.cacheTTL > 0 && cached != nil {
			e.staleFallback("default", "default", err)
			return cached.ruleset, nil
		}
		return nil, err
	}

	if cached != nil && cached.version == version && cached.exists == exists {
		e.mu.Lock()
		e.defaultCache = &cachedDefault{checkedAt: time.Now(), version: version, exists: exists, ruleset: cached.ruleset}
		e.mu.Unlock()
		return cached.ruleset, nil
	}

	if !exists {
		e.mu.Lock()
		e.defaultCache = &cachedDefault{checkedAt: time.Now(), version: version, exists: false}
		e.mu.Unlock()
		return nil, nil
	}

	const logID = "default"
	start := time.Now()
	if e.tracer != nil {
		var span trace.Span
		ctx, span = e.tracer.Start(ctx, "rules.compile", trace.WithAttributes(attribute.String("client", logID)))
		defer span.End()
	}

	raw, err := e.store.LoadRawDefault(ctx)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	entries, err := parseDefaultRuleset(raw)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	// Same best-effort uuid-mint-then-restat as a per-client file
	// (lookupIP), just over every entry missing one in a single blob
	// write instead of one file per client.
	minted := false
	for i := range entries {
		if entries[i].rule.UUID == "" {
			entries[i].rule.UUID = uuid.NewString()
			minted = true
		}
	}
	if minted {
		if data, merr := marshalCanonical(entries); merr == nil {
			if serr := e.store.SaveDefault(ctx, data); serr != nil {
				if e.log != nil {
					e.log.Warn("rules: failed to persist minted default uuid(s)", "err", serr.Error())
				}
			} else if newVersion, newExists, serr2 := e.store.StatDefault(ctx); serr2 == nil {
				version, exists = newVersion, newExists
			}
		}
	}

	var prev *DefaultRuleset
	if cached != nil {
		prev = cached.ruleset
	}
	compiled, err := compileParsedEntries(entries, prev)
	if err != nil {
		e.compileFailed(ctx, logID, start, err)
		return nil, err
	}

	e.mu.Lock()
	wasCached := e.defaultCache != nil && e.defaultCache.exists
	e.defaultCache = &cachedDefault{checkedAt: time.Now(), version: version, exists: exists, ruleset: compiled}
	e.mu.Unlock()

	if e.log != nil {
		reason := "first load"
		if wasCached {
			reason = "hot-reload"
		}
		e.log.Info("default ruleset compiled", "reason", reason, "buckets", len(entries))
	}
	e.metrics.RuleCompile(ctx, "ok", time.Since(start))

	return compiled, nil
}

func (e *RuleEngine) compileFailed(ctx context.Context, logID string, start time.Time, err error) {
	if e.log != nil {
		e.log.Warn("rule file compile failed", "client", logID, "err", err.Error())
	}
	e.metrics.RuleCompile(ctx, "error", time.Since(start))
}

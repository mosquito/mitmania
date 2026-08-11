package rules

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
)

// TestLookupRequest_WorkedExampleOrdering exercises first-match-wins
// ordering: narrow *.github.com rules (/token, DELETE) must win over the
// broad *.github.com rule that follows them, and reversing the order
// would make them dead code — this asserts the actual (correct) order
// behaves as documented.
func TestLookupRequest_WorkedExampleOrdering(t *testing.T) {
	compiled := mustCompile(t, `{
	  "http": [
	    { "match": { "host": "*.github.com", "path": "/token" },
	      "request": [ {"action":"raise","params":{"http":403,"body":"Declined"}} ] },
	    { "match": { "host": "*.github.com", "method": "DELETE" },
	      "request": [ {"action":"raise","params":{"http":403,"body":"No way"}} ] },
	    { "match": { "host": "*.github.com" },
	      "request": [ {"action":"header.add","params":{"Authorization":"..."}} ] },
	    { "match": {} }
	  ]
	}`)
	rs := &RuleSet{rules: compiled}

	tests := []struct {
		name       string
		in         MsgInput
		wantAction string // action name of the first request[] entry on the winning rule
	}{
		{
			name: "narrow path rule wins over broad host rule",
			in: MsgInput{
				ConnInput: ConnInput{Host: "api.github.com"},
				Path:      "/token",
				Method:    "GET",
				Header:    http.Header{},
			},
			wantAction: "raise",
		},
		{
			name: "narrow method rule wins over broad host rule",
			in: MsgInput{
				ConnInput: ConnInput{Host: "api.github.com"},
				Path:      "/repos/x",
				Method:    "DELETE",
				Header:    http.Header{},
			},
			wantAction: "raise",
		},
		{
			name: "broad rule catches everything else on that host",
			in: MsgInput{
				ConnInput: ConnInput{Host: "api.github.com"},
				Path:      "/repos/x",
				Method:    "GET",
				Header:    http.Header{},
			},
			wantAction: "header.add",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, ok := rs.LookupRequest(tt.in)
			if !ok {
				t.Fatalf("LookupRequest: no match")
			}
			if len(r.request) == 0 || r.request[0].Name != tt.wantAction {
				t.Fatalf("winning rule's first request action = %+v, want %q", r.request, tt.wantAction)
			}
		})
	}
}

// TestLookupRequest_StrictFirstMatch_NoCascading asserts the confirmed
// semantics: exactly one rule's pipeline runs, never an accumulation of
// every matching rule's actions.
func TestLookupRequest_StrictFirstMatch_NoCascading(t *testing.T) {
	compiled := mustCompile(t, `{
	  "http": [
	    { "match": { "host": "*.example.com" },
	      "request": [ {"action":"header.add","params":{"X-First":"1"}} ] },
	    { "match": { "host": "*.example.com" },
	      "request": [ {"action":"header.add","params":{"X-Second":"1"}} ] }
	  ]
	}`)
	rs := &RuleSet{rules: compiled}

	r, ok := rs.LookupRequest(MsgInput{ConnInput: ConnInput{Host: "a.example.com"}, Header: http.Header{}})
	if !ok {
		t.Fatalf("LookupRequest: no match")
	}
	if len(r.request) != 1 {
		t.Fatalf("winning rule has %d request actions, want 1 (only the first rule's)", len(r.request))
	}
	if _, ok := r.request[0].Params["X-First"]; !ok {
		t.Fatalf("winning rule is not the first one: %+v", r.request[0].Params)
	}
}

func TestLookupConn_MitmFalsePrecedesMessageRuleForSameHost(t *testing.T) {
	compiled := mustCompile(t, `{
	  "http": [
	    { "match": { "host": "internal.corp" }, "mitm": false },
	    { "match": { "host": "internal.corp", "path": "/admin" },
	      "request": [ {"action":"block"} ] }
	  ]
	}`)
	rs := &RuleSet{rules: compiled}

	mitm, matched := rs.LookupConn(ConnInput{Host: "internal.corp", Port: "443", Proto: "https"})
	if !matched {
		t.Fatalf("LookupConn: no match")
	}
	if mitm {
		t.Fatalf("mitm = true, want false (mitm:false rule should win, being first)")
	}
}

func TestLookupConn_NoMatch(t *testing.T) {
	compiled := mustCompile(t, `{"http":[{"match":{"host":"only-this.example.com"}}]}`)
	rs := &RuleSet{rules: compiled}
	_, matched := rs.LookupConn(ConnInput{Host: "other.example.com", Port: "443", Proto: "https"})
	if matched {
		t.Fatalf("LookupConn: unexpected match")
	}
}

func TestLookupRequest_HeaderMatch(t *testing.T) {
	compiled := mustCompile(t, `{
	  "http": [
	    { "match": { "host": "x", "header": {"X-Beta": "true"} },
	      "request": [ {"action":"header.add","params":{"X-Matched":"beta"}} ] },
	    { "match": { "host": "x" },
	      "request": [ {"action":"header.add","params":{"X-Matched":"default"}} ] }
	  ]
	}`)
	rs := &RuleSet{rules: compiled}

	h := http.Header{}
	h.Set("X-Beta", "true")
	r, ok := rs.LookupRequest(MsgInput{ConnInput: ConnInput{Host: "x"}, Header: h})
	if !ok {
		t.Fatalf("no match")
	}
	if r.request[0].Params["X-Matched"] != "beta" {
		t.Fatalf("matched rule = %+v, want the header-gated one", r.request[0].Params)
	}

	r2, ok := rs.LookupRequest(MsgInput{ConnInput: ConnInput{Host: "x"}, Header: http.Header{}})
	if !ok {
		t.Fatalf("no match")
	}
	if r2.request[0].Params["X-Matched"] != "default" {
		t.Fatalf("matched rule = %+v, want the default one", r2.request[0].Params)
	}
}

func TestRuleEngine_LookupCompilesFromStore(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.1")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{"host":"x"},"request":[{"action":"header.add","params":{"X-A":"1"}}]}]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(rs.rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rs.rules))
	}
}

func TestRuleEngine_UnknownClientGetsEmptyRuleSet(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(context.Background(), netip.MustParseAddr("10.0.0.99"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if _, matched := rs.LookupConn(ConnInput{Host: "anything", Port: "443", Proto: "https"}); matched {
		t.Fatalf("expected no match against an empty ruleset")
	}
}

// TestRuleEngine_LookupPicksUpDiskChangesAutomatically asserts there's no
// explicit reload step: Lookup notices a changed rule file (differing
// mtime+size) on its own, on the very next call.
func TestRuleEngine_LookupPicksUpDiskChangesAutomatically(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.2")
	if err := store.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
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

	// Different size guarantees the stat fingerprint changes regardless of
	// filesystem mtime resolution.
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs2.rules) != 1 {
		t.Fatalf("rules len after on-disk change = %d, want 1 (picked up with no explicit reload)", len(rs2.rules))
	}
}

// TestRuleEngine_LookupReusesCachedRuleSetWhenUnchanged asserts the stat
// check actually skips re-reading/recompiling when nothing changed,
// rather than coincidentally producing an equal-looking result each time.
func TestRuleEngine_LookupReusesCachedRuleSetWhenUnchanged(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.5")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs1 != rs2 {
		t.Fatalf("Lookup returned a freshly recompiled RuleSet despite an unchanged file")
	}
}

// TestRuleEngine_MintsUUIDForExistingFileWithoutOne verifies RuleFile's
// UUID contract — "operator-assigned, or a persisted uuid4 minted if
// absent": a file that exists but omits "uuid" gets one minted, persisted
// back to Storage, and
// exposed via RuleSet.UUID() — and a subsequent Lookup for the same
// client sees the SAME (now-persisted) uuid rather than minting again.
func TestRuleEngine_MintsUUIDForExistingFileWithoutOne(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.9")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs1, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs1.UUID() == "" {
		t.Fatalf("RuleSet.UUID() empty after Lookup on a file with no uuid — minting didn't happen")
	}

	persisted, err := store.Load(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.UUID != rs1.UUID() {
		t.Fatalf("minted uuid %q was not persisted back to Storage (on-disk uuid = %q)", rs1.UUID(), persisted.UUID)
	}

	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs2.UUID() != rs1.UUID() {
		t.Fatalf("uuid changed across a second Lookup: %q -> %q", rs1.UUID(), rs2.UUID())
	}
	if rs1 != rs2 {
		t.Fatalf("second Lookup recompiled instead of hitting cache — mint-then-persist must re-stat so the cached version matches")
	}
}

// TestRuleEngine_OperatorAssignedUUIDIsNeverOverwritten verifies the
// "operator-assigned" half of RuleFile's UUID contract: a file that
// already carries a uuid keeps it verbatim, with no mint/persist at all.
func TestRuleEngine_OperatorAssignedUUIDIsNeverOverwritten(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.10")
	if err := store.Save(ctx, client, []byte(`{"uuid":"operator-chosen","http":[]}`)); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs.UUID() != "operator-chosen" {
		t.Fatalf("UUID() = %q, want the operator-assigned \"operator-chosen\"", rs.UUID())
	}
}

// TestRuleEngine_NoFileGetsNoUUIDMinted verifies a client with no rule
// file at all gets an empty UUID, not a minted one — there's no file to
// persist a mint into, and "no file -> no match -> 511" already governs
// regardless.
func TestRuleEngine_NoFileGetsNoUUIDMinted(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(context.Background(), netip.MustParseAddr("10.0.0.11"))
	if err != nil {
		t.Fatal(err)
	}
	if rs.UUID() != "" {
		t.Fatalf("UUID() = %q, want empty for a client with no rule file", rs.UUID())
	}
}

// TestRuleEngine_Lookup_FallsBackToDefaultTable verifies a client with no
// per-IP override resolves via rules/default's matching bucket, and that
// a second Lookup hits the cache rather than recompiling.
func TestRuleEngine_Lookup_FallsBackToDefaultTable(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.5")

	defaultBlob := []byte(`{"0.0.0.0/0":{"uuid":"default-uuid","http":[{"match":{"host":"default.example"}}]},"::/0":{"http":[]}}`)
	if err := store.SaveDefault(ctx, defaultBlob); err != nil {
		t.Fatal(err)
	}

	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs.UUID() != "default-uuid" || len(rs.rules) != 1 {
		t.Fatalf("Lookup = uuid=%q rules=%d, want default-uuid, 1", rs.UUID(), len(rs.rules))
	}

	// A second call must hit the cache, not recompile.
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs != rs2 {
		t.Fatalf("second Lookup recompiled instead of hitting cache")
	}
}

// TestRuleEngine_Lookup_DefaultTableHotReload verifies a rules/default
// change is picked up with no explicit reload, same as a per-IP file.
func TestRuleEngine_Lookup_DefaultTableHotReload(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.6")

	if err := store.SaveDefault(ctx, []byte(`{"0.0.0.0/0":{"uuid":"u","http":[]},"::/0":{"http":[]}}`)); err != nil {
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

	if err := store.SaveDefault(ctx, []byte(`{"0.0.0.0/0":{"uuid":"u","http":[{"match":{}}]},"::/0":{"http":[]}}`)); err != nil {
		t.Fatal(err)
	}
	rs2, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs2.rules) != 1 {
		t.Fatalf("rules len after on-disk change = %d, want 1", len(rs2.rules))
	}
}

// TestRuleEngine_Lookup_ConvergesAcrossIndependentNodes proves the core
// distributed-operation claim: a rule change written through one node's
// Store becomes visible to a second, completely independent RuleEngine
// sharing only the same on-disk Storage — no direct communication
// between the two, exactly as two real fleet nodes only ever share
// Storage. Unlike TestRuleEngine_Lookup_DefaultTableHotReload, this uses
// two separate Storage clients and two separate engines, so a single
// shared engine's own cache can't be the reason a change is visible.
func TestRuleEngine_Lookup_ConvergesAcrossIndependentNodes(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.9")

	// Two independent Storage clients over the SAME directory — exactly
	// as two real node processes pointed at the same posix:// URL would
	// each open their own client.
	storeA := NewRuleStore(testStorage(t, dir))
	storeB := NewRuleStore(testStorage(t, dir))
	engineA := NewRuleEngine(storeA)
	engineB := NewRuleEngine(storeB)

	rsB, err := engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 0 {
		t.Fatalf("initial rules on node B = %d, want 0", len(rsB.rules))
	}

	// Node A alone receives the write (its control API PUT, simulated
	// here as a direct Store.Save) — node B's store/engine never touch
	// it.
	if err := storeA.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rsB, err = engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 1 {
		t.Fatalf("rules on node B after node A's write = %d, want 1", len(rsB.rules))
	}

	// Node A revokes; node B converges on the revocation too, not just
	// the initial write.
	if err := storeA.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	rsB, err = engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 0 {
		t.Fatalf("rules on node B after node A's revoke = %d, want 0", len(rsB.rules))
	}

	// Confirm symmetry, not just A -> B: node A converges on a write
	// made only through node B.
	if err := storeB.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rsA, err := engineA.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsA.rules) != 1 {
		t.Fatalf("rules on node A after node B's write = %d, want 1", len(rsA.rules))
	}
}

// TestRuleSet_Auth_NilWhenNoAuthBlock verifies a file with no "auth" key
// compiles to a nil Auth() — the default: source IP alone is identity,
// no credential gate.
func TestRuleSet_Auth_NilWhenNoAuthBlock(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.12")
	if err := store.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	engine := NewRuleEngine(store)
	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Auth() != nil {
		t.Fatalf("Auth() = %+v, want nil for a file with no auth block", rs.Auth())
	}
}

// TestRuleEngine_Lookup_InvalidAuthBlockFailsClosed verifies a malformed
// auth.http_proxy block (a malformed hash or an unknown scheme) is a
// load-time rejection on the RUNTIME path too, not just at PUT time —
// Lookup must error, not silently serve an empty/default auth config.
func TestRuleEngine_Lookup_InvalidAuthBlockFailsClosed(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("10.0.0.13")
	body := []byte(`{"auth":{"http_proxy":{"required":true}},"http":[]}`)
	if err := store.Save(ctx, client, body); err != nil {
		t.Fatal(err)
	}
	engine := NewRuleEngine(store)
	if _, err := engine.Lookup(ctx, client); err == nil {
		t.Fatalf("expected Lookup to fail closed on required:true with no scheme configured")
	}
}

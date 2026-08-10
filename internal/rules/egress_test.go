package rules

import (
	"context"
	"net/netip"
	"testing"
)

func TestCompileEgress_ValidatesFields(t *testing.T) {
	cases := []struct {
		name    string
		rule    EgressRule
		wantErr bool
	}{
		{"valid allow", EgressRule{CIDR: "10.0.0.0/8", Action: "allow"}, false},
		{"valid deny with port range", EgressRule{CIDR: "10.0.0.0/8", Port: "1024-65535", Action: "deny"}, false},
		{"valid with proto glob", EgressRule{CIDR: "0.0.0.0/0", Proto: "http", Action: "allow"}, false},
		{"bad cidr", EgressRule{CIDR: "not-a-cidr", Action: "allow"}, true},
		{"bad action", EgressRule{CIDR: "10.0.0.0/8", Action: "maybe"}, true},
		{"bad port", EgressRule{CIDR: "10.0.0.0/8", Port: "not-a-port", Action: "allow"}, true},
		{"inverted port range", EgressRule{CIDR: "10.0.0.0/8", Port: "100-50", Action: "allow"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileEgress([]EgressRule{tc.rule})
			if (err != nil) != tc.wantErr {
				t.Fatalf("CompileEgress(%+v): err=%v, wantErr=%v", tc.rule, err, tc.wantErr)
			}
		})
	}
}

func TestRuleSet_LookupEgress_FirstMatchWins(t *testing.T) {
	compiled, err := CompileEgress([]EgressRule{
		{CIDR: "127.0.0.0/8", Action: "deny"},
		{CIDR: "10.0.0.0/8", Port: "5432", Proto: "pg", Action: "allow"},
		{CIDR: "10.0.0.0/8", Action: "deny"},
		{CIDR: "0.0.0.0/0", Action: "allow"},
	})
	if err != nil {
		t.Fatalf("CompileEgress: %v", err)
	}
	rs := &RuleSet{egress: compiled}

	tests := []struct {
		addr      string
		port      uint16
		proto     string
		wantAllow bool
	}{
		{"127.0.0.1", 443, "http", false},    // loopback deny
		{"10.1.2.3", 5432, "pg", true},       // narrower allow before the broader deny
		{"10.1.2.3", 443, "http", false},     // falls through to the broader 10/8 deny
		{"93.184.216.34", 443, "http", true}, // public, trailing allow-all
		{"2001:db8::1", 443, "http", false},  // no matching family entry -> no-match -> deny
	}
	for _, tc := range tests {
		addr := netip.MustParseAddr(tc.addr)
		allow, matched := rs.LookupEgress(addr, tc.port, tc.proto)
		if allow != tc.wantAllow {
			t.Errorf("LookupEgress(%s, %d, %s) = allow=%v matched=%v, want allow=%v", tc.addr, tc.port, tc.proto, allow, matched, tc.wantAllow)
		}
	}
}

func TestRuleSet_LookupEgress_EmptyListDeniesEverything(t *testing.T) {
	rs := &RuleSet{egress: nil}
	allow, matched := rs.LookupEgress(netip.MustParseAddr("93.184.216.34"), 443, "http")
	if allow || matched {
		t.Fatalf("LookupEgress on empty list = allow=%v matched=%v, want false/false (deny-by-omission)", allow, matched)
	}
}

func TestRuleEngine_Lookup_OmittedEgressInheritsDefaultBucket(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.5")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	defaultBlob := []byte(`{"0.0.0.0/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"deny"}]},"::/0":{"http":[],"egress":[{"cidr":"::/0","action":"deny"}]}}`)
	if err := store.SaveDefault(ctx, defaultBlob); err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}
	engine := NewRuleEngine(store)

	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if allow, _ := rs.LookupEgress(netip.MustParseAddr("93.184.216.34"), 443, "http"); allow {
		t.Fatalf("rule file omitting \"egress\" did not inherit its rules/default bucket's egress policy")
	}
}

func TestRuleEngine_Lookup_ExplicitEmptyEgressIsNotDefault(t *testing.T) {
	store := NewRuleStore(testStorage(t, t.TempDir()))
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.6")
	if err := store.Save(ctx, client, []byte(`{"http":[{"match":{}}],"egress":[]}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	defaultBlob := []byte(`{"0.0.0.0/0":{"http":[],"egress":[{"cidr":"0.0.0.0/0","action":"allow"}]},"::/0":{"http":[],"egress":[{"cidr":"::/0","action":"allow"}]}}`)
	if err := store.SaveDefault(ctx, defaultBlob); err != nil {
		t.Fatalf("SaveDefault: %v", err)
	}
	engine := NewRuleEngine(store)

	rs, err := engine.Lookup(ctx, client)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// "egress": [] is present-but-empty, not an opt-out — it must NOT
	// inherit the (permissive) default bucket; an empty list matches
	// nothing, so everything is denied.
	if allow, _ := rs.LookupEgress(netip.MustParseAddr("93.184.216.34"), 443, "http"); allow {
		t.Fatalf("explicit \"egress\": [] allowed a request, want deny-by-omission")
	}
}

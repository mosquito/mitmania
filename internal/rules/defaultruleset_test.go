package rules

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCompileDefaultRuleset_SingleCatchAllPerFamilyCovers(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
}

func TestCompileDefaultRuleset_SplitHalvesCover(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/1":{"http":[]},"128.0.0.0/1":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
}

func TestCompileDefaultRuleset_GapIsRejectedWithDetail(t *testing.T) {
	// 0.0.0.0/1 covers 0.0.0.0-127.255.255.255, leaving the top half
	// uncovered.
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/1":{"http":[]},"::/0":{"http":[]}}`))
	if err == nil {
		t.Fatalf("expected an error for a v4 table missing the top half")
	}
	if !strings.Contains(err.Error(), "coverage gap") || !strings.Contains(err.Error(), "128.0.0.0") {
		t.Fatalf("error = %v, want it to name the gap starting at 128.0.0.0", err)
	}
}

func TestCompileDefaultRuleset_MissingFamilyEntirelyIsRejected(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[]}}`)) // no v6 entry at all
	if err == nil {
		t.Fatalf("expected an error for a table with no v6 coverage at all")
	}
	if !strings.Contains(err.Error(), "v6") {
		t.Fatalf("error = %v, want it to mention v6", err)
	}
}

func TestCompileDefaultRuleset_OverlapIsFine(t *testing.T) {
	// A broad catch-all plus a more specific override overlap by
	// definition — that's not a gap, it's resolved by ranking at Lookup
	// time.
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[]},"10.0.0.0/8":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
}

func TestCompileDefaultRuleset_InvalidCIDRRejected(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"not-a-cidr":{"http":[]},"::/0":{"http":[]}}`))
	if err == nil {
		t.Fatalf("expected an error for a malformed key")
	}
}

func TestCompileDefaultRuleset_InvalidBucketRuleRejected(t *testing.T) {
	// mitm:false with a message-phase match field is rejected at compile
	// time — a convenient, already-validated way to exercise "this
	// entry's http[] doesn't compile" here.
	_, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[{"match":{"path":"/x"},"mitm":false}]},"::/0":{"http":[]}}`))
	if err == nil {
		t.Fatalf("expected an error for an entry whose http[] doesn't compile")
	}
}

func TestDefaultRuleset_Lookup_LongestPrefixWins(t *testing.T) {
	d, _, err := CompileDefaultRuleset([]byte(`{
		"0.0.0.0/0":   {"uuid":"catch-all",        "http":[]},
		"10.0.0.0/8":  {"uuid":"corp-net",          "http":[]},
		"10.1.0.0/16": {"uuid":"corp-net-subnet",   "http":[]},
		"::/0":        {"uuid":"catch-all-v6",      "http":[]}
	}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}

	cases := []struct{ addr, want string }{
		{"8.8.8.8", "catch-all"},
		{"10.5.0.1", "corp-net"},
		{"10.1.2.3", "corp-net-subnet"},
		{"2001:db8::1", "catch-all-v6"},
	}
	for _, c := range cases {
		rs, ok := d.Lookup(netip.MustParseAddr(c.addr))
		if !ok {
			t.Fatalf("Lookup(%s): no match, want %s", c.addr, c.want)
		}
		if rs.UUID() != c.want {
			t.Errorf("Lookup(%s) = %q, want %q", c.addr, rs.UUID(), c.want)
		}
	}
}

func TestDefaultRuleset_Buckets_ExposesEveryEntry(t *testing.T) {
	d, _, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	if len(d.Buckets()) != 2 {
		t.Fatalf("Buckets() len = %d, want 2", len(d.Buckets()))
	}
}

// --- Sparse mask matching ---

func TestDefaultRuleset_SparseMask_MatchesFixedBytesOnly(t *testing.T) {
	// A /48 segment where byte 4 = availability zone, byte 5 = service
	// id; the mask picks out both bytes and ignores everything else,
	// including the bits in between.
	d, _, err := CompileDefaultRuleset([]byte(`{
		"2001:db8:0:0::/32":               {"uuid":"segment",  "http":[]},
		"2001:db8:0:0::/ffff:ffff:ffff::":  {"uuid":"az-svc",   "http":[]},
		"::/0":                             {"uuid":"catch-all","http":[]},
		"0.0.0.0/0":                        {"http":[]}
	}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}

	// 2001:db8: matches the /32 segment prefix; byte4:byte5 = 00:00
	// matches the az-svc mask's fixed (zero) bytes too, so the more
	// specific (larger mask value) entry wins.
	rs, ok := d.Lookup(netip.MustParseAddr("2001:db8::1"))
	if !ok || rs.UUID() != "az-svc" {
		t.Fatalf("Lookup(2001:db8::1) = ok=%v uuid=%q, want az-svc", ok, rs.UUID())
	}

	// Same segment, but byte4:byte5 differ from the az-svc entry's fixed
	// zero bytes (2001:0db8:0001:...) — falls through to the segment
	// prefix instead.
	rs, ok = d.Lookup(netip.MustParseAddr("2001:db8:1::1"))
	if !ok || rs.UUID() != "segment" {
		t.Fatalf("Lookup(2001:db8:1::1) = ok=%v uuid=%q, want segment", ok, rs.UUID())
	}

	rs, ok = d.Lookup(netip.MustParseAddr("2001:db9::1"))
	if !ok || rs.UUID() != "catch-all" {
		t.Fatalf("Lookup(2001:db9::1) = ok=%v uuid=%q, want catch-all", ok, rs.UUID())
	}
}

func TestDefaultRuleset_SparseMask_CanOutrankLongerPrefix(t *testing.T) {
	// A mask whose value is larger than a longer prefix's own mask value
	// wins over it — deliberately not longest-prefix semantics.
	d, _, err := CompileDefaultRuleset([]byte(`{
		"0.0.0.0/0":             {"uuid":"catch-all", "http":[]},
		"10.0.0.0/8":            {"uuid":"prefix-8",  "http":[]},
		"10.0.0.0/16":           {"uuid":"prefix-16", "http":[]},
		"10.0.0.0/255.255.255.0":{"uuid":"sparse",    "http":[]},
		"::/0":                  {"uuid":"v6",         "http":[]}
	}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	// 255.255.255.0 (/24-valued mask) > /16's mask (255.255.0.0) as a
	// big-endian integer, so it wins for an address matching all three.
	rs, ok := d.Lookup(netip.MustParseAddr("10.0.0.5"))
	if !ok || rs.UUID() != "sparse" {
		t.Fatalf("Lookup(10.0.0.5) = ok=%v uuid=%q, want sparse (larger mask value wins)", ok, rs.UUID())
	}
	// Outside the sparse entry's third octet but still in /16.
	rs, ok = d.Lookup(netip.MustParseAddr("10.0.1.5"))
	if !ok || rs.UUID() != "prefix-16" {
		t.Fatalf("Lookup(10.0.1.5) = ok=%v uuid=%q, want prefix-16", ok, rs.UUID())
	}
}

func TestDefaultRuleset_SparseMask_FamilyMismatchRejected(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"10.0.0.0/ffff:0:ffff::":{"http":[]},"::/0":{"http":[]}}`))
	if err == nil {
		t.Fatalf("expected an error for a v6-notation mask on a v4 address")
	}
}

func TestDefaultRuleset_SparseMask_InvalidMaskLiteralRejected(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{"10.0.0.0/not-a-mask":{"http":[]},"::/0":{"http":[]}}`))
	if err == nil {
		t.Fatalf("expected an error for an unparseable mask literal")
	}
}

// --- Normalization ---

func TestCompileDefaultRuleset_ContiguousMaskNormalizesToPrefixLen(t *testing.T) {
	_, canonical, err := CompileDefaultRuleset([]byte(`{"0.0.0.0/0":{"http":[]},"10.0.0.0/255.0.0.0":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	if !strings.Contains(string(canonical), `"10.0.0.0/8"`) {
		t.Fatalf("canonical = %s, want the contiguous mask normalized to /8", canonical)
	}
	if strings.Contains(string(canonical), "255.0.0.0") {
		t.Fatalf("canonical = %s, want the sparse-mask literal gone once normalized", canonical)
	}
}

func TestCompileDefaultRuleset_ExtraAddressBitsAreCleared(t *testing.T) {
	_, canonical, err := CompileDefaultRuleset([]byte(`{"10.1.2.3/8":{"http":[]},"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	if !strings.Contains(string(canonical), `"10.0.0.0/8"`) {
		t.Fatalf("canonical = %s, want 10.1.2.3/8's host bits cleared to 10.0.0.0/8", canonical)
	}

	_, canonical2, err := CompileDefaultRuleset([]byte(`{"10.1.0.0/255.0.255.0":{"http":[]},"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	if !strings.Contains(string(canonical2), `"10.0.0.0/255.0.255.0"`) {
		t.Fatalf("canonical = %s, want 10.1.0.0/255.0.255.0's out-of-mask bit cleared to 10.0.0.0/255.0.255.0", canonical2)
	}
}

func TestCompileDefaultRuleset_NormalizedDuplicateKeysCollapseLastWins(t *testing.T) {
	// "10.0.0.0/255.0.0.0" and "10.0.0.0/8" normalize to the identical
	// entry — the later one in source order must win, not be added
	// alongside as a second competing entry.
	d, canonical, err := CompileDefaultRuleset([]byte(`{
		"10.0.0.0/255.0.0.0": {"uuid":"first",  "http":[]},
		"10.0.0.0/8":          {"uuid":"second", "http":[]},
		"0.0.0.0/0":           {"http":[]},
		"::/0":                {"http":[]}
	}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
	rs, ok := d.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || rs.UUID() != "second" {
		t.Fatalf("Lookup(10.1.2.3) = ok=%v uuid=%q, want second (the later duplicate wins)", ok, rs.UUID())
	}
	if strings.Count(string(canonical), `"10.0.0.0/8"`) != 1 {
		t.Fatalf("canonical = %s, want exactly one 10.0.0.0/8 entry, not two competing ones", canonical)
	}
}

// --- Coverage obligation scoped to plain-prefix entries only ---

func TestCompileDefaultRuleset_CoverageIgnoresSparseEntries(t *testing.T) {
	// A sparse mask contributes nothing to the coverage obligation in
	// either direction: it doesn't need to help cover the space, and its
	// presence doesn't excuse a genuine prefix gap.
	_, _, err := CompileDefaultRuleset([]byte(`{
		"10.0.0.0/255.0.255.0": {"http":[]},
		"::/0":                  {"http":[]}
	}`))
	if err == nil {
		t.Fatalf("expected a v4 coverage error — the sparse entry alone must not satisfy coverage")
	}
	if !strings.Contains(err.Error(), "v4") {
		t.Fatalf("error = %v, want it to mention v4", err)
	}
}

func TestCompileDefaultRuleset_SparseEntryAlongsideValidCoverageIsFine(t *testing.T) {
	_, _, err := CompileDefaultRuleset([]byte(`{
		"0.0.0.0/0":             {"http":[]},
		"10.0.0.0/255.0.255.0":  {"http":[]},
		"::/0":                  {"http":[]}
	}`))
	if err != nil {
		t.Fatalf("CompileDefaultRuleset: %v", err)
	}
}

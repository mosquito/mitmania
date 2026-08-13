package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func boolPtr(v bool) *bool { return &v }

func compileIndexedRuleSet(t testing.TB, source []Rule) *RuleSet {
	t.Helper()
	compiled, err := Compile(RuleFile{HTTP: source})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return newRuleSet(compiled, nil, "", nil)
}

func TestHostCandidateIndex_ImportedSuffixFirstMatchOrdering(t *testing.T) {
	rs := compileIndexedRuleSet(t, []Rule{
		// Arbitrary regex stays in fallback and must still beat the indexed
		// generated-list rule below.
		{Match: Match{Host: `re:^ads\..*`}, MITM: boolPtr(false)},
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:ads\.example|tracker\.example)$`}},
		{Match: Match{}, MITM: boolPtr(false)},
	})

	if mitm, matched := rs.LookupConn(ConnInput{Host: "ads.example", Port: "443", Proto: "https"}); !matched || mitm {
		t.Fatalf("ads.example = mitm:%v matched:%v, want first fallback rule's false/true", mitm, matched)
	}
	if mitm, matched := rs.LookupConn(ConnInput{Host: "sub.tracker.example", Port: "443", Proto: "https"}); !matched || !mitm {
		t.Fatalf("sub.tracker.example = mitm:%v matched:%v, want indexed true/true", mitm, matched)
	}
	if mitm, matched := rs.LookupConn(ConnInput{Host: "ordinary.example", Port: "443", Proto: "https"}); !matched || mitm {
		t.Fatalf("ordinary.example = mitm:%v matched:%v, want catch-all false/true", mitm, matched)
	}
}

func TestHostCandidateIndex_ExceptionCanPrecedeParentBlock(t *testing.T) {
	rs := compileIndexedRuleSet(t, []Rule{
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:allowed\.ads\.example)$`}, MITM: boolPtr(false)},
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:ads\.example)$`}},
		{Match: Match{}, MITM: boolPtr(false)},
	})

	if mitm, _ := rs.LookupConn(ConnInput{Host: "sub.allowed.ads.example"}); mitm {
		t.Fatal("specific exception lost first-match precedence to parent block")
	}
	if mitm, _ := rs.LookupConn(ConnInput{Host: "other.ads.example"}); !mitm {
		t.Fatal("parent suffix block did not match sibling hostname")
	}
}

func TestHostCandidateIndex_AllowBetweenDenyRulesPreservesOrder(t *testing.T) {
	rs := compileIndexedRuleSet(t, []Rule{
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:evil\.good\.ads\.example)$`}},
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:good\.ads\.example)$`}, MITM: boolPtr(false)},
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:ads\.example)$`}},
		{Match: Match{}, MITM: boolPtr(false)},
	})

	cases := []struct {
		host     string
		wantMITM bool
	}{
		{"evil.good.ads.example", true},
		{"safe.good.ads.example", false},
		{"other.ads.example", true},
		{"unrelated.example", false},
	}
	for _, tc := range cases {
		mitm, matched := rs.LookupConn(ConnInput{Host: tc.host})
		if !matched || mitm != tc.wantMITM {
			t.Errorf("LookupConn(%q) = mitm:%v matched:%v, want %v/true", tc.host, mitm, matched, tc.wantMITM)
		}
	}
}

func TestHostCandidateIndex_WildcardUsesExistingFullMatcher(t *testing.T) {
	rs := compileIndexedRuleSet(t, []Rule{
		{Match: Match{Host: `*.example.com`}},
		{Match: Match{}, MITM: boolPtr(false)},
	})

	// path.Match's existing whole-host '*' semantics include dots. The tree
	// indexes only example.com and leaves this final decision to matcher.match.
	if mitm, _ := rs.LookupConn(ConnInput{Host: "a.b.example.com"}); !mitm {
		t.Fatal("wildcard rule semantics changed during indexing")
	}
	if mitm, _ := rs.LookupConn(ConnInput{Host: "example.com"}); mitm {
		t.Fatal("wildcard candidate bypassed full matcher verification")
	}
}

func TestHostCandidateIndex_LookupRequestPreservesMessagePhaseOrdering(t *testing.T) {
	rs := compileIndexedRuleSet(t, []Rule{
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:api\.ads\.example)$`, Method: http.MethodPost}},
		{Match: Match{Host: `re:(?i)(?:^|\.)(?:ads\.example)$`, Method: http.MethodGet}},
	})

	rule, matched := rs.LookupRequest(MsgInput{
		ConnInput: ConnInput{Host: "api.ads.example", Port: "443", Proto: "https"},
		Method:    http.MethodGet,
	})
	if !matched || rule != &rs.rules[1] {
		t.Fatalf("LookupRequest selected %p matched:%v, want second rule %p", rule, matched, &rs.rules[1])
	}
}

func TestHostCandidateIndex_MoreThanStackCandidateCapacity(t *testing.T) {
	source := make([]Rule, 0, 41)
	for port := 1; port <= 40; port++ {
		source = append(source, Rule{Match: Match{Port: fmt.Sprint(port)}})
	}
	source = append(source, Rule{Match: Match{}, MITM: boolPtr(false)})
	rs := compileIndexedRuleSet(t, source)

	if mitm, matched := rs.LookupConn(ConnInput{Host: "example.com", Port: "443"}); !matched || mitm {
		t.Fatalf("overflow candidate lookup = mitm:%v matched:%v, want false/true", mitm, matched)
	}
}

func TestImportedSuffixRegexRejectsNonCanonicalRegex(t *testing.T) {
	canonical, err := compileMatcher(`re:(?i)(?:^|\.)(?:ads\.example|tracker\.example)$`)
	if err != nil {
		t.Fatal(err)
	}
	if hosts, ok := importedSuffixRegex(canonical); !ok || len(hosts) != 2 {
		t.Fatalf("canonical regex = hosts:%v ok:%v, want two/true", hosts, ok)
	}

	for _, pattern := range []string{
		`re:(?i)(?:^|\.)(?:ads.*\.example)$`,
		`re:(?:^|\.)(?:ads\.example)$`,
		`re:(?i)(?:^|\.)(?:ads\.example)/path$`,
	} {
		m, err := compileMatcher(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if hosts, ok := importedSuffixRegex(m); ok {
			t.Fatalf("importedSuffixRegex(%q) = %v, true; want fallback", pattern, hosts)
		}
	}
}

func TestImportedSuffixMatcherPreservesRegexSemantics(t *testing.T) {
	m, err := compileMatcher(`re:(?i)(?:^|\.)(?:ads\.example|tracker\.example)$`)
	if err != nil {
		t.Fatal(err)
	}
	if m.re != nil || len(m.suffixes) != 2 {
		t.Fatalf("canonical generated regex was not compiled as suffixes: %#v", m)
	}
	for _, host := range []string{"ads.example", "sub.ADS.EXAMPLE", "Tracker.Example"} {
		if !m.match(host) {
			t.Errorf("match(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"notads.example", "ads.example.invalid", "ads.example."} {
		if m.match(host) {
			t.Errorf("match(%q) = true, want false", host)
		}
	}
}

// TestHostCandidateIndex_ScalesTo100kGeneratedHosts exercises the index at
// the scale it exists for: tools/adblock_to_mitmania.py's default
// max-regex-chars (12,000) groups roughly 570 ~21-byte hosts per generated
// re: rule, so a combined easylist/easyprivacy/AdGuard-sized import lands
// around 100k hosts across a couple hundred rules — not the 300-rule/1
// host-per-rule shape the other tests and benchmark above use. This is a
// correctness test with timing logged for visibility. It deliberately has no
// wall-clock assertion: CI runs tests under race and atomic coverage
// instrumentation, while performance regressions belong in the benchmark.
func TestHostCandidateIndex_ScalesTo100kGeneratedHosts(t *testing.T) {
	const total = 100_000
	const perChunk = 571

	hosts := make([]string, total)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("trk-%06d.adexample.net", i)
	}

	source := make([]Rule, 0, total/perChunk+2)
	for start := 0; start < total; start += perChunk {
		end := min(start+perChunk, total)
		atoms := make([]string, 0, end-start)
		for _, h := range hosts[start:end] {
			atoms = append(atoms, strings.ReplaceAll(h, ".", `\.`))
		}
		source = append(source, Rule{
			Match: Match{Host: `re:(?i)(?:^|\.)(?:` + strings.Join(atoms, "|") + `)$`},
		})
	}
	source = append(source, Rule{Match: Match{}, MITM: boolPtr(false)})
	t.Logf("%d generated hosts chunked into %d rules", total, len(source))

	compileStart := time.Now()
	compiled, err := Compile(RuleFile{HTTP: source})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	index := buildHostCandidateIndex(compiled)
	compileElapsed := time.Since(compileStart)
	t.Logf("compiled+indexed %d rules in %s", len(source), compileElapsed)
	rs := newRuleSetWithHostIndex(compiled, index, nil, "", nil)

	lookupStart := time.Now()
	for _, i := range []int{0, total / 4, total / 2, total - 1} {
		host := "www." + hosts[i]
		if mitm, matched := rs.LookupConn(ConnInput{Host: host, Port: "443", Proto: "https"}); !matched || !mitm {
			t.Errorf("listed host %q (index %d) = mitm:%v matched:%v, want true/true", host, i, mitm, matched)
		}
	}
	if mitm, matched := rs.LookupConn(ConnInput{Host: "not-in-any-generated-list.example", Port: "443", Proto: "https"}); !matched || mitm {
		t.Errorf("unlisted host = mitm:%v matched:%v, want catch-all false/true", mitm, matched)
	}
	t.Logf("5 spot lookups across %d rules in %s", len(source), time.Since(lookupStart))

	httpJSON, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("marshal generated http policy: %v", err)
	}
	// rules/default repeats the identical http[] policy once per IPv4/IPv6
	// catch-all bucket (compileParsedEntries dedups the compiled/indexed
	// form once the bytes are identical, but the PUT body itself still
	// carries both copies) — mirror that doubling here for a realistic
	// comparison against internal/control's 64<<20 rules/default limit.
	const controlMaxDefaultRulesetBytes = 64 << 20
	doubled := 2 * len(httpJSON)
	t.Logf("%d hosts -> %d bytes http[] JSON, %d doubled for v4+v6 (%.1f%% of the %d-byte rules/default limit)",
		total, len(httpJSON), doubled, 100*float64(doubled)/float64(controlMaxDefaultRulesetBytes), controlMaxDefaultRulesetBytes)
}

func BenchmarkLookupConnHostCandidates(b *testing.B) {
	source := make([]Rule, 0, 301)
	for n := 0; n < 300; n++ {
		source = append(source, Rule{Match: Match{Host: fmt.Sprintf(`re:(?i)(?:^|\.)(?:ads-%03d\.example)$`, n)}})
	}
	source = append(source, Rule{Match: Match{}, MITM: boolPtr(false)})
	indexed := compileIndexedRuleSet(b, source)
	legacy := &RuleSet{rules: indexed.rules}
	in := ConnInput{Host: "sub.ads-299.example", Port: "443", Proto: "https"}

	b.Run("indexed", func(b *testing.B) {
		for b.Loop() {
			indexed.LookupConn(in)
		}
	})
	b.Run("linear", func(b *testing.B) {
		for b.Loop() {
			legacy.LookupConn(in)
		}
	})
}

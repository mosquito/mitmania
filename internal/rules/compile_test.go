package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, jsonDoc string) []CompiledRule {
	t.Helper()
	var rf RuleFile
	if err := json.Unmarshal([]byte(jsonDoc), &rf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	compiled, err := Compile(rf)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return compiled
}

func mustFailCompile(t *testing.T, jsonDoc string) error {
	t.Helper()
	var rf RuleFile
	if err := json.Unmarshal([]byte(jsonDoc), &rf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	_, err := Compile(rf)
	if err == nil {
		t.Fatalf("Compile: expected error, got nil")
	}
	return err
}

func TestCompile_WorkedExampleFromSpec(t *testing.T) {
	doc := `{
	  "http": [
	    { "match": { "host": "*.github.com", "path": "/token" },
	      "request":  [ {"action":"raise","params":{"http":403,"body":"Declined"}} ] },
	    { "match": { "host": "*.github.com", "method": "DELETE" },
	      "request":  [ {"action":"raise","params":{"http":403,"body":"No way"}} ] },
	    { "match": { "host": "*.github.com" },
	      "request":  [ {"action":"header.add","params":{"Authorization":"..."}},
	                    {"action":"header.set","params":{"User-Agent":"mitmania/1.2.3"}} ],
	      "response": [ {"action":"header.set","params":{"Location":null}} ] },
	    { "match": { "host": "internal.corp" }, "mitm": false },
	    { "match": {} }
	  ]
	}`
	compiled := mustCompile(t, doc)
	if len(compiled) != 5 {
		t.Fatalf("len(compiled) = %d, want 5", len(compiled))
	}
	if compiled[3].mitm {
		t.Fatalf("rule 3 (internal.corp) mitm = true, want false")
	}
	for i, r := range compiled {
		if i == 3 {
			continue
		}
		if !r.mitm {
			t.Fatalf("rule %d mitm = false, want default true", i)
		}
	}
}

func TestCompile_RejectsUnknownAction(t *testing.T) {
	err := mustFailCompile(t, `{"http":[{"match":{},"request":[{"action":"bogus"}]}]}`)
	if !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("error = %v, want mention of unknown action", err)
	}
}

func TestCompile_RejectsRaiseInResponse(t *testing.T) {
	err := mustFailCompile(t, `{"http":[{"match":{},"response":[{"action":"raise","params":{"http":403}}]}]}`)
	if !strings.Contains(err.Error(), "unknown or phase-inapplicable") {
		t.Fatalf("error = %v, want phase-inapplicable", err)
	}
}

func TestCompile_RejectsBlockInResponse(t *testing.T) {
	err := mustFailCompile(t, `{"http":[{"match":{},"response":[{"action":"block"}]}]}`)
	if !strings.Contains(err.Error(), "unknown or phase-inapplicable") {
		t.Fatalf("error = %v, want phase-inapplicable", err)
	}
}

func TestCompile_RejectsMitmFalseWithMessageFields(t *testing.T) {
	for _, doc := range []string{
		`{"http":[{"match":{"host":"x","path":"/a"},"mitm":false}]}`,
		`{"http":[{"match":{"host":"x","method":"GET"},"mitm":false}]}`,
		`{"http":[{"match":{"host":"x","header":{"X-Foo":"bar"}},"mitm":false}]}`,
	} {
		err := mustFailCompile(t, doc)
		if !strings.Contains(err.Error(), "mitm:false") {
			t.Fatalf("doc %q: error = %v, want mitm:false complaint", doc, err)
		}
	}
}

func TestCompile_InvalidRegexRejected(t *testing.T) {
	mustFailCompile(t, `{"http":[{"match":{"host":"re:("}}]}`)
}

func TestCompile_ConnectionAcceptFalseCompiles(t *testing.T) {
	compiled := mustCompile(t, `{"http":[{"match":{"host":"ads.example"},"connection":{"accept":false}}]}`)
	if len(compiled) != 1 {
		t.Fatalf("len(compiled) = %d, want 1", len(compiled))
	}
	if !compiled[0].deny {
		t.Fatalf("deny = false, want true")
	}
	if compiled[0].mitm {
		t.Fatalf("mitm = true, want false when connection.accept is false")
	}
}

func TestCompile_RejectsConnectionAcceptFalseWithMitm(t *testing.T) {
	for _, doc := range []string{
		`{"http":[{"match":{"host":"x"},"connection":{"accept":false},"mitm":true}]}`,
		`{"http":[{"match":{"host":"x"},"connection":{"accept":false},"mitm":false}]}`,
	} {
		err := mustFailCompile(t, doc)
		if !strings.Contains(err.Error(), "cannot also set mitm") {
			t.Fatalf("doc %q: error = %v, want connection+mitm complaint", doc, err)
		}
	}
}

func TestCompile_RejectsConnectionAcceptFalseWithMessageFields(t *testing.T) {
	for _, doc := range []string{
		`{"http":[{"match":{"host":"x","path":"/a"},"connection":{"accept":false}}]}`,
		`{"http":[{"match":{"host":"x","method":"GET"},"connection":{"accept":false}}]}`,
		`{"http":[{"match":{"host":"x","header":{"X-Foo":"bar"}},"connection":{"accept":false}}]}`,
	} {
		err := mustFailCompile(t, doc)
		if !strings.Contains(err.Error(), "cannot carry message-phase match fields") {
			t.Fatalf("doc %q: error = %v, want connection message-phase complaint", doc, err)
		}
	}
}

func TestCompile_RejectsConnectionAcceptFalseWithActions(t *testing.T) {
	for _, doc := range []string{
		`{"http":[{"match":{"host":"x"},"connection":{"accept":false},"request":[{"action":"block"}]}]}`,
		`{"http":[{"match":{"host":"x"},"connection":{"accept":false},"response":[{"action":"header.set","params":{"X-A":"1"}}]}]}`,
	} {
		err := mustFailCompile(t, doc)
		if !strings.Contains(err.Error(), "cannot carry request/response actions") {
			t.Fatalf("doc %q: error = %v, want connection actions complaint", doc, err)
		}
	}
}

func TestCompile_RejectsConnectionMissingAccept(t *testing.T) {
	err := mustFailCompile(t, `{"http":[{"match":{"host":"x"},"connection":{}}]}`)
	if !strings.Contains(err.Error(), "connection.accept is required") {
		t.Fatalf("error = %v, want connection.accept required complaint", err)
	}
}

// TestCompile_ConnectionAcceptTrueIsNoOp verifies accept:true imposes none
// of accept:false's restrictions — it's the already-default phase-1
// behavior stated explicitly, so it composes freely with mitm, message
// fields, and actions, unlike accept:false.
func TestCompile_ConnectionAcceptTrueIsNoOp(t *testing.T) {
	compiled := mustCompile(t, `{"http":[
	  {"match":{"host":"x","path":"/a"},"connection":{"accept":true},"mitm":true,
	   "request":[{"action":"block"}]}
	]}`)
	if len(compiled) != 1 {
		t.Fatalf("len(compiled) = %d, want 1", len(compiled))
	}
	if compiled[0].deny {
		t.Fatalf("deny = true, want false for connection.accept:true")
	}
	if !compiled[0].mitm {
		t.Fatalf("mitm = false, want true (explicit mitm:true preserved)")
	}
}

func TestMatcher_Glob(t *testing.T) {
	m, err := compileMatcher("*.github.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		in   string
		want bool
	}{
		{"api.github.com", true},
		{"github.com", false}, // "*" requires at least the dot-prefixed segment under path.Match semantics
		{"api.gitlab.com", false},
	} {
		if got := m.match(tt.in); got != tt.want {
			t.Errorf("match(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestMatcher_Regex(t *testing.T) {
	m, err := compileMatcher("re:^api-[0-9]+\\.example\\.com$")
	if err != nil {
		t.Fatal(err)
	}
	if !m.match("api-42.example.com") {
		t.Errorf("expected match")
	}
	if m.match("api-x.example.com") {
		t.Errorf("expected no match")
	}
}

func TestMatcher_EmptyIsWildcard(t *testing.T) {
	m, err := compileMatcher("")
	if err != nil {
		t.Fatal(err)
	}
	if !m.match("literally-anything") {
		t.Errorf("expected empty pattern to match everything")
	}
}

func TestCompile_HeaderNamesCanonicalized(t *testing.T) {
	doc := `{"http":[{"match":{"host":"x","header":{"x-foo":"bar"}}}]}`
	compiled := mustCompile(t, doc)
	if _, ok := compiled[0].msgHeader["X-Foo"]; !ok {
		t.Fatalf("header match key not canonicalized: %+v", compiled[0].msgHeader)
	}
}

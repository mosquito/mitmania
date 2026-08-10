package rules

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestDocumentationRuleSnippets keeps copy-pasted documentation examples on
// the production decode and compile paths. It intentionally does not maintain
// a second, test-only interpretation of the rule format.
func TestDocumentationRuleSnippets(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "docs", "tested", "rules", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no documentation rule snippets found")
	}

	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var rf RuleFile
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&rf); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := requireJSONEOF(dec); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if _, err := Compile(rf); err != nil {
				t.Fatalf("http rules: %v", err)
			}
			if rf.Egress != nil {
				if _, err := CompileEgress(rf.Egress); err != nil {
					t.Fatalf("egress rules: %v", err)
				}
			}
			if _, err := CompileAuth(rf.Auth); err != nil {
				t.Fatalf("auth: %v", err)
			}
		})
	}
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return &trailingJSONError{}
}

type trailingJSONError struct{}

func (*trailingJSONError) Error() string { return "multiple JSON values" }

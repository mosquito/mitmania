package config

import "testing"

func TestParseLogFormat(t *testing.T) {
	for _, valid := range []string{"plain", "json", "cat"} {
		if got, err := ParseLogFormat(valid); err != nil || got != valid {
			t.Errorf("ParseLogFormat(%q) = %q, %v; want %q, nil", valid, got, err, valid)
		}
	}
	if _, err := ParseLogFormat("yaml"); err == nil {
		t.Fatalf("ParseLogFormat(\"yaml\"): expected error, got nil")
	}
}

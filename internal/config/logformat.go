package config

import "fmt"

// logFormats are --log-format's accepted values: plain (the default,
// human-readable text), json (structured, for log collectors/storage —
// VictoriaLogs, Loki, etc.), and cat (bare message only — no timestamp,
// level, or fields — for quick manual tailing/piping).
var logFormats = map[string]bool{"plain": true, "json": true, "cat": true}

// ParseLogFormat validates --log-format's value.
func ParseLogFormat(s string) (string, error) {
	if !logFormats[s] {
		return "", fmt.Errorf("must be one of plain, json, cat; got %q", s)
	}
	return s, nil
}

package config

import (
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warning", slog.LevelWarn},
		{"Warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"critical", LevelCritical},
	}
	for _, tc := range cases {
		got, err := ParseLogLevel(tc.in)
		if err != nil {
			t.Errorf("ParseLogLevel(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseLogLevel_Invalid(t *testing.T) {
	if _, err := ParseLogLevel("warn"); err == nil {
		t.Fatalf("ParseLogLevel(\"warn\"): expected error (only \"warning\" is accepted), got nil")
	}
	if _, err := ParseLogLevel("verbose"); err == nil {
		t.Fatalf("ParseLogLevel(\"verbose\"): expected error, got nil")
	}
}

func TestLevelName(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARNING"},
		{slog.LevelError, "ERROR"},
		{LevelCritical, "CRITICAL"},
	}
	for _, tc := range cases {
		if got := LevelName(tc.level); got != tc.want {
			t.Errorf("LevelName(%v) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

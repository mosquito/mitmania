package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// LevelCritical is a custom slog level above the built-in LevelError —
// slog only defines Debug/Info/Warn/Error natively, and --log-level's
// "critical" has nowhere else to map to.
const LevelCritical = slog.Level(12)

var logLevels = map[string]slog.Level{
	"debug":    slog.LevelDebug,
	"info":     slog.LevelInfo,
	"warning":  slog.LevelWarn,
	"error":    slog.LevelError,
	"critical": LevelCritical,
}

// ParseLogLevel maps --log-level's value (debug, info, warning, error, or
// critical — case-insensitive) to a slog.Level.
func ParseLogLevel(s string) (slog.Level, error) {
	level, ok := logLevels[strings.ToLower(s)]
	if !ok {
		return 0, fmt.Errorf("must be one of debug, info, warning, error, critical; got %q", s)
	}
	return level, nil
}

// LevelName renders level the way mitmania's own log output does — the
// five words above, not slog's default abbreviations ("WARN") or its
// generic offset notation for levels it doesn't know ("ERROR+4" for
// LevelCritical). Intended as a slog.HandlerOptions.ReplaceAttr helper.
func LevelName(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "DEBUG"
	case slog.LevelInfo:
		return "INFO"
	case slog.LevelWarn:
		return "WARNING"
	case slog.LevelError:
		return "ERROR"
	case LevelCritical:
		return "CRITICAL"
	default:
		return level.String()
	}
}

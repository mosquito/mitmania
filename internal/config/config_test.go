package config

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func validKey() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

func TestParseHappyPath(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.HTTPProxy == nil || cfg.HTTPProxy.Port != 3128 {
		t.Fatalf("HTTPProxy = %+v, want port 3128", cfg.HTTPProxy)
	}
	if want := "/run/user/1000/mitmania.sock"; cfg.Control.Scheme != "unix" || cfg.Control.Path != want {
		t.Fatalf("Control default = %+v, want unix://%s", cfg.Control, want)
	}
	if len(cfg.ClusterKey) != 32 {
		t.Fatalf("ClusterKey len = %d, want 32", len(cfg.ClusterKey))
	}
	if cfg.HTTPHeaderLimit != 64<<10 {
		t.Fatalf("HTTPHeaderLimit = %d, want %d", cfg.HTTPHeaderLimit, 64<<10)
	}
	if cfg.HTTPBodyWindow != 64<<10 {
		t.Fatalf("HTTPBodyWindow = %d, want %d", cfg.HTTPBodyWindow, 64<<10)
	}
	if cfg.HTTPConnectTimeout != 2*time.Second {
		t.Fatalf("HTTPConnectTimeout = %v, want 2s", cfg.HTTPConnectTimeout)
	}
	if cfg.HTTPReadTimeout != 60*time.Second {
		t.Fatalf("HTTPReadTimeout = %v, want 60s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPConnectTries != 3 {
		t.Fatalf("HTTPConnectTries = %d, want 3", cfg.HTTPConnectTries)
	}
	if cfg.HTTP2ConnectTimeout != 2*time.Second {
		t.Fatalf("HTTP2ConnectTimeout = %v, want 2s", cfg.HTTP2ConnectTimeout)
	}
	if cfg.HTTP2ReadTimeout != 60*time.Second {
		t.Fatalf("HTTP2ReadTimeout = %v, want 60s", cfg.HTTP2ReadTimeout)
	}
	if cfg.HTTP2ConnectTries != 3 {
		t.Fatalf("HTTP2ConnectTries = %d, want 3", cfg.HTTP2ConnectTries)
	}
}

func TestParseTimeoutRetryFlagsOverride(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-timeout-connect", "5",
		"--http-timeout-read", "30",
		"--http-connect-tries", "1",
		"--http2-timeout-connect", "7",
		"--http2-timeout-read", "45",
		"--http2-connect-tries", "2",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.HTTPConnectTimeout != 5*time.Second {
		t.Fatalf("HTTPConnectTimeout = %v, want 5s", cfg.HTTPConnectTimeout)
	}
	if cfg.HTTPReadTimeout != 30*time.Second {
		t.Fatalf("HTTPReadTimeout = %v, want 30s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPConnectTries != 1 {
		t.Fatalf("HTTPConnectTries = %d, want 1", cfg.HTTPConnectTries)
	}
	if cfg.HTTP2ConnectTimeout != 7*time.Second {
		t.Fatalf("HTTP2ConnectTimeout = %v, want 7s", cfg.HTTP2ConnectTimeout)
	}
	if cfg.HTTP2ReadTimeout != 45*time.Second {
		t.Fatalf("HTTP2ReadTimeout = %v, want 45s", cfg.HTTP2ReadTimeout)
	}
	if cfg.HTTP2ConnectTries != 2 {
		t.Fatalf("HTTP2ConnectTries = %d, want 2", cfg.HTTP2ConnectTries)
	}
}

func TestParseRejectsNonPositiveTimeoutsAndTries(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	for _, flagName := range []string{
		"http-timeout-connect", "http-timeout-read", "http-connect-tries",
		"http2-timeout-connect", "http2-timeout-read", "http2-connect-tries",
	} {
		_, err := Parse([]string{
			"--storage", "posix:///tmp/mitmania-cache",
			"--listen-http-proxy", "tcp://*:3128",
			"--cluster-key", validKey(),
			"--" + flagName, "0",
		})
		if err == nil || !strings.Contains(err.Error(), flagName) {
			t.Fatalf("flag %s=0: expected error mentioning %q, got %v", flagName, flagName, err)
		}
	}
}

func TestParseHTTPFramingFlagsOverride(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-header-limit", "8k",
		"--http-body-window", "0",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.HTTPHeaderLimit != 8<<10 {
		t.Fatalf("HTTPHeaderLimit = %d, want %d", cfg.HTTPHeaderLimit, 8<<10)
	}
	if cfg.HTTPBodyWindow != 0 {
		t.Fatalf("HTTPBodyWindow = %d, want 0", cfg.HTTPBodyWindow)
	}
}

func TestParseRejectsZeroHeaderLimit(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-header-limit", "0",
	})
	if err == nil || !strings.Contains(err.Error(), "http-header-limit") {
		t.Fatalf("Parse: expected http-header-limit error, got %v", err)
	}
}

func TestParseDefaultsControlToXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if want := "/run/user/1000/mitmania.sock"; cfg.Control.Path != want {
		t.Fatalf("Control.Path = %q, want %q", cfg.Control.Path, want)
	}
}

// TestParseRequiresControlWhenXDGRuntimeDirUnset: per the XDG Base
// Directory spec, XDG_RUNTIME_DIR has no filesystem fallback (it's meant
// to be tmpfs-backed with specific ownership set up by the session
// manager) — so unlike --cache-dir, --control has nothing safe to
// synthesize and must be required explicitly.
func TestParseRequiresControlWhenXDGRuntimeDirUnset(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--control") {
		t.Fatalf("Parse: expected --control-required error, got %v", err)
	}
}

func TestParseDefaultsCacheDirToXDG(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/xdg-cache")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if want := "posix:///xdg-cache/mitmania"; cfg.Storage != want {
		t.Fatalf("Storage = %q, want %q", cfg.Storage, want)
	}
}

// TestParseDefaultsCacheDirFallsBackToHome checks the spec-defined
// fallback: $HOME/.cache/mitmania, not $HOME/.local/cache/mitmania.
func TestParseDefaultsCacheDirFallsBackToHome(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if want := "posix:///home/testuser/.cache/mitmania"; cfg.Storage != want {
		t.Fatalf("Storage = %q, want %q", cfg.Storage, want)
	}
}

// TestParseIgnoresRelativeXDGCacheHome: the spec says a relative
// XDG_CACHE_HOME value must be treated as if unset.
func TestParseIgnoresRelativeXDGCacheHome(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "relative/path")
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if want := "posix:///home/testuser/.cache/mitmania"; cfg.Storage != want {
		t.Fatalf("Storage = %q, want %q", cfg.Storage, want)
	}
}

func TestParseExplicitCacheDirOverridesDefault(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "/xdg-cache")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///explicit/cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if want := "posix:///explicit/cache"; cfg.Storage != want {
		t.Fatalf("Storage = %q, want %q", cfg.Storage, want)
	}
}

func TestParseRequiresClusterKey(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
	})
	if err == nil || !strings.Contains(err.Error(), "cluster-key") {
		t.Fatalf("Parse: expected cluster-key error, got %v", err)
	}
}

func TestParseRejectsShortClusterKey(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", short,
	})
	if err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("Parse: expected short-key error, got %v", err)
	}
}

func TestParseRequiresADataListener(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "no data listeners") {
		t.Fatalf("Parse: expected no-data-listeners error, got %v", err)
	}
}

func TestParseRejectsTProxyNotYetImplemented(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--listen-http-tproxy", "tcp://*:3129",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("Parse: expected not-yet-implemented error, got %v", err)
	}
}

func TestParseRejectsRedirectNotYetImplemented(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--listen-http-redirect", "tcp://*:3130",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "not yet implemented") {
		t.Fatalf("Parse: expected not-yet-implemented error, got %v", err)
	}
}

func TestParseAcceptsUnixControl(t *testing.T) {
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "unix:///tmp/mitmania-proxy.sock",
		"--control", "tcp://127.0.0.1:9000",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.HTTPProxy.Scheme != "unix" {
		t.Fatalf("HTTPProxy.Scheme = %q, want unix", cfg.HTTPProxy.Scheme)
	}
	if cfg.Control.Scheme != "tcp" || cfg.Control.Port != 9000 {
		t.Fatalf("Control = %+v, want tcp:9000", cfg.Control)
	}
}

func TestParseShortFlags(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"-s", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"-c", "tcp://127.0.0.1:9000",
		"-k", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.Storage != "posix:///tmp/mitmania-cache" {
		t.Fatalf("Storage = %q (from -s)", cfg.Storage)
	}
	if cfg.Control.Port != 9000 {
		t.Fatalf("Control.Port = %d (from -c), want 9000", cfg.Control.Port)
	}
	if len(cfg.ClusterKey) != 32 {
		t.Fatalf("ClusterKey len = %d (from -k), want 32", len(cfg.ClusterKey))
	}
}

func TestParseEnvVars(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("MITMANIA_STORAGE", "posix:///env/cache")
	t.Setenv("MITMANIA_CLUSTER_KEY", validKey())
	t.Setenv("MITMANIA_LISTEN_HTTP_PROXY", "tcp://*:3128")
	t.Setenv("MITMANIA_HTTP_TIMEOUT_CONNECT", "9")

	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.Storage != "posix:///env/cache" {
		t.Fatalf("Storage = %q, want posix:///env/cache (from MITMANIA_STORAGE)", cfg.Storage)
	}
	if len(cfg.ClusterKey) != 32 {
		t.Fatalf("ClusterKey len = %d, want 32 (from MITMANIA_CLUSTER_KEY)", len(cfg.ClusterKey))
	}
	if cfg.HTTPProxy == nil || cfg.HTTPProxy.Port != 3128 {
		t.Fatalf("HTTPProxy = %+v (from MITMANIA_LISTEN_HTTP_PROXY)", cfg.HTTPProxy)
	}
	if cfg.HTTPConnectTimeout != 9*time.Second {
		t.Fatalf("HTTPConnectTimeout = %v, want 9s (from MITMANIA_HTTP_TIMEOUT_CONNECT)", cfg.HTTPConnectTimeout)
	}
}

func TestParseFlagOverridesEnvVar(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	t.Setenv("MITMANIA_STORAGE", "posix:///env/cache")
	cfg, err := Parse([]string{
		"--storage", "posix:///flag/cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.Storage != "posix:///flag/cache" {
		t.Fatalf("Storage = %q, want posix:///flag/cache (explicit flag should win over env)", cfg.Storage)
	}
}

func TestParseLogLevelDefaultsToInfo(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("LogLevel = %v, want Info (default)", cfg.LogLevel)
	}
}

func TestParseLogLevelFlag(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--log-level", "debug",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("LogLevel = %v, want Debug", cfg.LogLevel)
	}
}

func TestParseRejectsInvalidLogLevel(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--log-level", "verbose",
	})
	if err == nil || !strings.Contains(err.Error(), "--log-level") {
		t.Fatalf("Parse: expected --log-level error, got %v", err)
	}
}

func TestParseHelpReturnsErrHelp(t *testing.T) {
	_, err := Parse([]string{"--help"})
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("Parse([--help]): err = %v, want ErrHelp", err)
	}

	_, err = Parse([]string{"-h"})
	if !errors.Is(err, ErrHelp) {
		t.Fatalf("Parse([-h]): err = %v, want ErrHelp", err)
	}
}

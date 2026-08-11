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
		"outcall-timeout-connect", "outcall-timeout-read", "outcall-max-inflight",
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

// TestParseRequiresStorageWhenHomeUnset exercises defaultStorageURL's
// os.UserHomeDir error path (no $HOME to fall back to) and Parse's own
// "could not determine a default" guard when neither --storage nor
// $XDG_CACHE_HOME nor $HOME can supply one.
func TestParseRequiresStorageWhenHomeUnset(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--storage is required") {
		t.Fatalf("Parse: expected --storage-required error, got %v", err)
	}
}

func TestParseRejectsMalformedStorageURL(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix://%zzbad",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--storage") {
		t.Fatalf("Parse: expected --storage invalid-URL error, got %v", err)
	}
}

func TestParseRejectsUnsupportedStorageScheme(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "http://example.invalid/",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("Parse: expected --storage unsupported-scheme error, got %v", err)
	}
}

func TestParseRejectsInvalidClusterKeyBase64(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", "not-valid-base64!!!",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("Parse: expected invalid-base64 error, got %v", err)
	}
}

// TestParseRejectsUnknownFlag exercises kong's own parser.Parse error path,
// distinct from every field-level validation Parse performs afterward.
func TestParseRejectsUnknownFlag(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--not-a-real-flag", "1",
	})
	if err == nil || !strings.Contains(err.Error(), "not-a-real-flag") {
		t.Fatalf("Parse: expected unknown-flag error, got %v", err)
	}
}

func TestParseRejectsMalformedListenHTTPProxyAddr(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--listen-http-proxy") {
		t.Fatalf("Parse: expected --listen-http-proxy addr error, got %v", err)
	}
}

func TestParseRejectsUnsupportedListenHTTPProxyScheme(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "udp://*:3128",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--listen-http-proxy") || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("Parse: expected --listen-http-proxy scheme error, got %v", err)
	}
}

func TestParseRejectsUnsupportedListenHTTPSProxyScheme(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-https-proxy", "udp://*:8443",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--listen-https-proxy") {
		t.Fatalf("Parse: expected --listen-https-proxy scheme error, got %v", err)
	}
}

// TestParseAcceptsListenHTTPSProxy is the valid-path companion to the
// scheme-rejection test above: no existing test successfully parses
// --listen-https-proxy at all, so its default-CN fallback went uncovered.
func TestParseAcceptsListenHTTPSProxy(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-https-proxy", "tcp://*:8443",
		"--cluster-key", validKey(),
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.HTTPSProxy == nil {
		t.Fatal("HTTPSProxy = nil, want set")
	}
	if cfg.HTTPSProxy.Addr.Scheme != "tcp" || cfg.HTTPSProxy.Addr.Port != 8443 {
		t.Fatalf("HTTPSProxy.Addr = %+v, want tcp:8443", cfg.HTTPSProxy.Addr)
	}
	if len(cfg.HTTPSProxy.Names) != 1 || cfg.HTTPSProxy.Names[0] != "Internal Proxy" {
		t.Fatalf("HTTPSProxy.Names = %v, want default [\"Internal Proxy\"]", cfg.HTTPSProxy.Names)
	}
}

func TestParseRejectsMalformedControlAddr(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--control", "tcp://*",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--control") {
		t.Fatalf("Parse: expected --control addr error, got %v", err)
	}
}

func TestParseRejectsUnsupportedControlScheme(t *testing.T) {
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--control", "udp://127.0.0.1:9000",
		"--cluster-key", validKey(),
	})
	if err == nil || !strings.Contains(err.Error(), "--control") {
		t.Fatalf("Parse: expected --control scheme error, got %v", err)
	}
}

func TestParseRejectsMalformedHeaderLimit(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-header-limit", "notanumber",
	})
	if err == nil || !strings.Contains(err.Error(), "--http-header-limit") {
		t.Fatalf("Parse: expected --http-header-limit parse error, got %v", err)
	}
}

func TestParseRejectsMalformedBodyWindow(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-body-window", "notanumber",
	})
	if err == nil || !strings.Contains(err.Error(), "--http-body-window") {
		t.Fatalf("Parse: expected --http-body-window parse error, got %v", err)
	}
}

// TestParseRejectsOverflowedBodyWindow: ParseSize only rejects an
// explicitly negative numeric part — it doesn't check for int overflow
// after applying the k/m/g multiplier, so a value like this multiplies
// past math.MaxInt64 and wraps negative. Parse's own bodyWindow < 0 guard
// is what actually catches this, distinct from ParseSize's own error path.
func TestParseRejectsOverflowedBodyWindow(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--http-body-window", "8589934592g",
	})
	if err == nil || !strings.Contains(err.Error(), "--http-body-window") || !strings.Contains(err.Error(), "must be >= 0") {
		t.Fatalf("Parse: expected --http-body-window overflow error, got %v", err)
	}
}

func TestParseRejectsInvalidLogFormat(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--log-format", "xml",
	})
	if err == nil || !strings.Contains(err.Error(), "--log-format") {
		t.Fatalf("Parse: expected --log-format error, got %v", err)
	}
}

func TestParseLogFormatFlag(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--log-format", "json",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("LogFormat = %q, want json", cfg.LogFormat)
	}
}

func TestParseRejectsUnsupportedOtelMetricsScheme(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-metrics", "ftp://example.invalid/",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-metrics") {
		t.Fatalf("Parse: expected --otel-metrics scheme error, got %v", err)
	}
}

func TestParseAcceptsOtelMetrics(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-metrics", "http://localhost:9090/metrics",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.OtelMetrics != "http://localhost:9090/metrics" {
		t.Fatalf("OtelMetrics = %q, want http://localhost:9090/metrics", cfg.OtelMetrics)
	}
}

func TestParseRejectsUnsupportedOtelTracesScheme(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-traces", "ftp://example.invalid/",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-traces") {
		t.Fatalf("Parse: expected --otel-traces scheme error, got %v", err)
	}
}

func TestParseAcceptsOtelTraces(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	cfg, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-traces", "stdout://",
	})
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	if cfg.OtelTraces != "stdout://" {
		t.Fatalf("OtelTraces = %q, want stdout://", cfg.OtelTraces)
	}
}

func TestParseRejectsOutOfRangeOtelSampleRatio(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-sample-ratio", "1.5",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-sample-ratio") {
		t.Fatalf("Parse: expected --otel-sample-ratio range error, got %v", err)
	}
}

func TestParseRejectsMalformedOtelSpoolMaxSize(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-spool-max-size", "notanumber",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-spool-max-size") {
		t.Fatalf("Parse: expected --otel-spool-max-size parse error, got %v", err)
	}
}

func TestParseRejectsZeroOtelSpoolMaxSize(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-spool-max-size", "0",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-spool-max-size") {
		t.Fatalf("Parse: expected --otel-spool-max-size must-be->0 error, got %v", err)
	}
}

func TestParseRejectsZeroOtelSpoolMaxAge(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--otel-spool-max-age", "0s",
	})
	if err == nil || !strings.Contains(err.Error(), "--otel-spool-max-age") {
		t.Fatalf("Parse: expected --otel-spool-max-age must-be->0 error, got %v", err)
	}
}

func TestParseRejectsInvalidTrustedProxiesEntry(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	_, err := Parse([]string{
		"--storage", "posix:///tmp/mitmania-cache",
		"--listen-http-proxy", "tcp://*:3128",
		"--cluster-key", validKey(),
		"--trusted-proxies", "not-an-ip",
	})
	if err == nil || !strings.Contains(err.Error(), "--trusted-proxies") {
		t.Fatalf("Parse: expected --trusted-proxies error, got %v", err)
	}
}

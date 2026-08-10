package main

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"mitmania/internal/config"
)

func TestMaskURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "s3 credentials redacted",
			in:   "s3://AKIAEXAMPLE:supersecretkey@s3.amazonaws.com/?bucket=mitmania&region=us-east-1",
			want: "s3://<REDACTED>@s3.amazonaws.com/?bucket=mitmania&region=us-east-1",
		},
		{
			name: "posix path has no userinfo to mask",
			in:   "posix:///var/cache/mitmania",
			want: "posix:///var/cache/mitmania",
		},
		{
			name: "unparseable value is redacted outright, not logged verbatim",
			in:   "://not a url",
			want: "<REDACTED>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := maskURL(tc.in)
			if got != tc.want {
				t.Errorf("maskURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "supersecretkey") || strings.Contains(got, "AKIAEXAMPLE") {
				t.Errorf("maskURL(%q) leaked a credential: %q", tc.in, got)
			}
		})
	}
}

func TestLogConfig_NeverLogsClusterKeyOrRawCredentials(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := &config.Config{
		Storage:             "s3://AKIAEXAMPLE:supersecretkey@s3.amazonaws.com/?bucket=mitmania&region=us-east-1",
		ClusterKey:          []byte("do-not-log-this-cluster-key-3210"),
		HTTPHeaderLimit:     65536,
		HTTPBodyWindow:      65536,
		HTTPConnectTimeout:  2 * time.Second,
		HTTPReadTimeout:     60 * time.Second,
		HTTPConnectTries:    3,
		HTTP2ConnectTimeout: 2 * time.Second,
		HTTP2ReadTimeout:    60 * time.Second,
		HTTP2ConnectTries:   3,
		LogLevel:            slog.LevelInfo,
	}
	httpProxy, err := config.ParseAddr("tcp://*:3128")
	if err != nil {
		t.Fatal(err)
	}
	cfg.HTTPProxy = &httpProxy
	control, err := config.ParseAddr("tcp://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Control = control

	logConfig(log, cfg)

	out := buf.String()
	if strings.Contains(out, "supersecretkey") || strings.Contains(out, "AKIAEXAMPLE") {
		t.Fatalf("logConfig leaked S3 credentials into the log:\n%s", out)
	}
	if strings.Contains(out, string(cfg.ClusterKey)) {
		t.Fatalf("logConfig leaked the cluster key into the log:\n%s", out)
	}
	for _, want := range []string{
		"config: storage", "config: listeners", "config: http framing",
		"config: http upstream", "config: http2 upstream", "config: logging",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("logConfig output missing %q; got:\n%s", want, out)
		}
	}
}

func TestNewLogger_Formats(t *testing.T) {
	for _, format := range []string{"plain", "json", "cat"} {
		if _, err := config.ParseLogFormat(format); err != nil {
			t.Fatalf("test format %q isn't valid per config.ParseLogFormat: %v", format, err)
		}
	}
	// newLogger itself always writes to os.Stderr — exercised for real via
	// TestCatHandler below (the one format with custom, hand-rolled
	// behavior) and via the smoke test in cmd's own manual verification;
	// this just guards the switch doesn't panic/nil-deref for any valid
	// format value.
	for _, format := range []string{"plain", "json", "cat", "bogus"} {
		if got := newLogger(slog.LevelInfo, format); got == nil {
			t.Errorf("newLogger(Info, %q) = nil", format)
		}
	}
}

func TestCatHandler_MessagePlusFields_NoTimeOrLevel(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(&catHandler{level: slog.LevelInfo, w: &buf, mu: &sync.Mutex{}})

	log.Info("hello world", "key", "value", "another", 42)
	log.With("bound", "x").Info("second line")

	got := buf.String()
	want := "hello world key=value another=42\nsecond line bound=x\n"
	if got != want {
		t.Fatalf("cat output = %q, want %q", got, want)
	}
	if strings.Contains(got, "time=") || strings.Contains(got, "level=") {
		t.Fatalf("cat output still carries time/level: %q", got)
	}
}

func TestCatHandler_RespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(&catHandler{level: slog.LevelWarn, w: &buf, mu: &sync.Mutex{}})

	log.Info("should be suppressed")
	log.Warn("should appear")

	got := buf.String()
	if strings.Contains(got, "suppressed") {
		t.Fatalf("catHandler logged below its configured level: %q", got)
	}
	if !strings.Contains(got, "should appear") {
		t.Fatalf("catHandler dropped a record at its configured level: %q", got)
	}
}

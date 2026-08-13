package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mitmania/internal/cert"
	"mitmania/internal/flowsink"
	"mitmania/internal/rules"
	"mitmania/internal/storage"
)

// fakeStorage wraps a real backing storage.Storage and lets a test force
// any one operation to fail on demand — the handler-level equivalent of
// the outcall probe's "unreachable broker" fixture, exercising the
// Storage-error branches every handler has (LoadRaw/Save/Delete/Count/
// Flush) without needing a corrupted-on-disk backend, which isn't
// portable across sandboxes (e.g. root bypasses permission-based
// failures).
type fakeStorage struct {
	storage.Storage

	failGet          bool
	failPut          bool
	failDelete       bool
	failDeletePrefix bool
	failList         bool
	failStat         bool
}

var errFakeStorage = errors.New("fake storage failure")

func (f *fakeStorage) Get(ctx context.Context, key string) ([]byte, storage.Version, error) {
	if f.failGet {
		return nil, "", errFakeStorage
	}
	return f.Storage.Get(ctx, key)
}

func (f *fakeStorage) Put(ctx context.Context, key string, data []byte) error {
	if f.failPut {
		return errFakeStorage
	}
	return f.Storage.Put(ctx, key, data)
}

func (f *fakeStorage) Delete(ctx context.Context, key string) error {
	if f.failDelete {
		return errFakeStorage
	}
	return f.Storage.Delete(ctx, key)
}

func (f *fakeStorage) DeletePrefix(ctx context.Context, prefix string) error {
	if f.failDeletePrefix {
		return errFakeStorage
	}
	return f.Storage.DeletePrefix(ctx, prefix)
}

func (f *fakeStorage) Stat(ctx context.Context, key string) (storage.Version, error) {
	if f.failStat {
		return "", errFakeStorage
	}
	return f.Storage.Stat(ctx, key)
}

func (f *fakeStorage) List(ctx context.Context, prefix string) ([]storage.Entry, error) {
	if f.failList {
		return nil, errFakeStorage
	}
	return f.Storage.List(ctx, prefix)
}

// newTestControlWithFakeStorage is newTestControl, but Store and Cache sit
// on top of a fakeStorage instead of talking to disk directly — CA
// generation still goes through the real backing PosixStorage first, so
// only the failure flags set by the test (after construction) affect the
// handler calls under test.
func newTestControlWithFakeStorage(t *testing.T) (*Control, *fakeStorage) {
	t.Helper()
	dir := t.TempDir()
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}

	backing, err := storage.NewPosixStorage(dir)
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	ca, err := cert.LoadOrGenerateCA(context.Background(), backing, ck)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	fs := &fakeStorage{Storage: backing}
	cache := cert.NewCertCache(fs, ck, ca)
	store := rules.NewRuleStore(fs)

	c := &Control{
		CA:    ca,
		Cache: cache,
		Store: store,
		Flow:  &flowsink.Counters{},
	}
	return c, fs
}

// errReader always fails on Read — simulates a client that hangs up mid
// body, the only way to reach handlePutRule/handlePutDefault's
// io.ReadAll error branch (a real net/http round trip can't get a
// broken body to the handler: the client-side Transport would fail the
// request before it's ever sent).
type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errors.New("simulated read failure") }

func serveHTTP(c *Control, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, req)
	return rec
}

func TestControl_HandleGetRuleInvalidIP(t *testing.T) {
	c, _ := newTestControl(t)
	rec := serveHTTP(c, http.MethodGet, "/rules/not-an-ip", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}
}

func TestControl_HandlePutRuleInvalidIP(t *testing.T) {
	c, _ := newTestControl(t)
	rec := serveHTTP(c, http.MethodPut, "/rules/not-an-ip", strings.NewReader(`{"http":[]}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}
}

// TestControl_HandlePutRuleRejectionsDoNotPersist covers the handler-level
// validation branches beyond what TestControl_PutRulesRejectsInvalid
// already exercises (malformed JSON, unknown action, mitm:false+headers):
// an oversized body (413, rejected before JSON is even parsed) and a
// syntactically valid rule file whose egress[] entry fails
// rules.CompileEgress. Both must fail closed — the PUT never reaches
// Storage.
func TestControl_HandlePutRuleRejectionsDoNotPersist(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		doc        string
		wantStatus int
	}{
		{
			name:       "oversized body",
			ip:         "10.0.0.30",
			doc:        strings.Repeat("a", maxRuleFileBytes+100),
			wantStatus: http.StatusRequestEntityTooLarge,
		},
		{
			name:       "invalid egress CIDR",
			ip:         "10.0.0.31",
			doc:        `{"http":[],"egress":[{"cidr":"not-a-cidr","action":"allow"}]}`,
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestControl(t)

			rec := serveHTTP(c, http.MethodPut, "/rules/"+tt.ip, strings.NewReader(tt.doc))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body)
			}

			getRec := serveHTTP(c, http.MethodGet, "/rules/"+tt.ip, nil)
			if got := strings.TrimSpace(getRec.Body.String()); got != `{"http":[]}` {
				t.Fatalf("GET after rejected PUT = %s, want the unwritten default", got)
			}
		})
	}
}

func TestControl_HandlePutRuleBodyReadError(t *testing.T) {
	c, _ := newTestControl(t)

	rec := serveHTTP(c, http.MethodPut, "/rules/10.0.0.32", errReader{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}

	getRec := serveHTTP(c, http.MethodGet, "/rules/10.0.0.32", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{"http":[]}` {
		t.Fatalf("GET after rejected PUT = %s, want the unwritten default", got)
	}
}

func TestControl_HandlePutDefaultBodyReadError(t *testing.T) {
	c, _ := newTestControl(t)

	rec := serveHTTP(c, http.MethodPut, "/rules/default", errReader{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body)
	}

	getRec := serveHTTP(c, http.MethodGet, "/rules/default", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{}` {
		t.Fatalf("GET after rejected PUT = %s, want the unwritten default", got)
	}
}

func TestControl_HandlePutDefaultOversizedBody(t *testing.T) {
	c, _ := newTestControl(t)

	body := strings.Repeat("a", maxDefaultRulesetBytes+100)
	rec := serveHTTP(c, http.MethodPut, "/rules/default", strings.NewReader(body))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body)
	}

	getRec := serveHTTP(c, http.MethodGet, "/rules/default", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{}` {
		t.Fatalf("GET after rejected PUT = %s, want the unwritten default", got)
	}
}

func TestControl_HandlePutDefaultMayExceedPerClientLimit(t *testing.T) {
	c, _ := newTestControl(t)

	// JSON permits leading whitespace, giving this focused limit test a valid
	// document larger than maxRuleFileBytes without constructing or compiling
	// an artificial million-byte matcher. The default-table endpoint accepts
	// it and persists the small canonical representation; PUT /rules/{ip}
	// remains independently capped at maxRuleFileBytes.
	body := strings.Repeat(" ", maxRuleFileBytes+1) + `{"0.0.0.0/0":{"http":[]},"::/0":{"http":[]}}`
	rec := serveHTTP(c, http.MethodPut, "/rules/default", strings.NewReader(body))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body)
	}
}

// TestControl_HandlePutDefault_HundredThousandGeneratedHosts exercises the
// actual synchronous compile path a fleet-wide adblock-style import runs
// through: rules.CompileDefaultRuleset (including host-index construction)
// blocks this handler, and only then is the result persisted. It mirrors
// tools/adblock_to_mitmania.py's default chunking (max-regex-chars 12,000,
// ~571 ~21-byte hosts per generated re: rule) at a combined
// easylist/easyprivacy/AdGuard-import scale. Not a strict perf gate — CI
// hardware varies — but a regression here means a real blocklist import
// would start timing out or stalling the control API.
func TestControl_HandlePutDefault_HundredThousandGeneratedHosts(t *testing.T) {
	c, _ := newTestControl(t)

	const total = 100_000
	const perChunk = 571

	var httpRules strings.Builder
	httpRules.WriteByte('[')
	for start := 0; start < total; start += perChunk {
		end := min(start+perChunk, total)
		if start > 0 {
			httpRules.WriteByte(',')
		}
		httpRules.WriteString(`{"match":{"host":"re:(?i)(?:^|\\.)(?:`)
		for i := start; i < end; i++ {
			if i > start {
				httpRules.WriteByte('|')
			}
			fmt.Fprintf(&httpRules, `trk-%06d\\.adexample\\.net`, i)
		}
		httpRules.WriteString(`)$"}}`)
	}
	httpRules.WriteString(`,{"match":{},"mitm":false}]`)

	body := fmt.Sprintf(`{"0.0.0.0/0":{"http":%s},"::/0":{"http":%s}}`, httpRules.String(), httpRules.String())
	t.Logf("generated PUT /rules/default body: %d bytes for %d hosts", len(body), total)

	start := time.Now()
	rec := serveHTTP(c, http.MethodPut, "/rules/default?validate=false", strings.NewReader(body))
	elapsed := time.Since(start)
	t.Logf("PUT /rules/default with %d generated hosts took %s", total, elapsed)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("PUT /rules/default with %d hosts took %s, want well under 5s", total, elapsed)
	}
}

func TestControl_HandleGetDefaultEmpty(t *testing.T) {
	c, _ := newTestControl(t)

	rec := serveHTTP(c, http.MethodGet, "/rules/default", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{}` {
		t.Fatalf("body = %s, want {} for a never-configured rules/default", got)
	}
}

// TestControl_HandlePutDefaultProbeFailsForABucket mirrors
// TestControl_PutRuleProbesOutcallAndRejectsOnUnreachableBroker for
// PUT /rules/default: an unreachable broker referenced by any one bucket
// must reject the whole table, before any bucket (even the unrelated
// one) is written.
func TestControl_HandlePutDefaultProbeFailsForABucket(t *testing.T) {
	c, _ := newTestControl(t)
	c = withOutcall(c)

	doc := `{"0.0.0.0/0":{"http":[{"match":{},"request":[{"action":"webhook","params":{"url":"https://127.0.0.1:1"}}]}]},"::/0":{"http":[]}}`
	rec := serveHTTP(c, http.MethodPut, "/rules/default", strings.NewReader(doc))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (probe should fail against an unreachable broker); body=%s", rec.Code, rec.Body)
	}

	getRec := serveHTTP(c, http.MethodGet, "/rules/default", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{}` {
		t.Fatalf("GET after rejected PUT = %s, want the unwritten default", got)
	}
}

// TestControl_StorageFailuresSurfaceAs500 covers every handler whose only
// remaining uncovered branch is "the underlying Storage/CertCache call
// itself failed" — distinct from the validation-rejection paths above,
// and only reachable by injecting a Storage error since these calls
// otherwise always succeed against a healthy backend.
func TestControl_StorageFailuresSurfaceAs500(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(fs *fakeStorage)
		method, path string
	}{
		{"GET /stats: cache Count fails", func(fs *fakeStorage) { fs.failList = true }, http.MethodGet, "/stats"},
		{"DELETE /cache: cache Flush fails", func(fs *fakeStorage) { fs.failDeletePrefix = true }, http.MethodDelete, "/cache"},
		{"GET /rules/{ip}: LoadRaw fails", func(fs *fakeStorage) { fs.failGet = true }, http.MethodGet, "/rules/10.0.0.1"},
		{"DELETE /rules/{ip}: Delete fails", func(fs *fakeStorage) { fs.failDelete = true }, http.MethodDelete, "/rules/10.0.0.1"},
		{"GET /rules/default: LoadRawDefault fails", func(fs *fakeStorage) { fs.failGet = true }, http.MethodGet, "/rules/default"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, fs := newTestControlWithFakeStorage(t)
			tt.setup(fs)

			rec := serveHTTP(c, tt.method, tt.path, nil)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body)
			}
		})
	}
}

// TestControl_HandlePutRuleStorageSaveFails verifies that a Storage.Save
// failure after successful validation still fails closed: the client
// gets a 500, and — once the injected failure is cleared — a follow-up
// GET proves the rejected body never landed on disk.
func TestControl_HandlePutRuleStorageSaveFails(t *testing.T) {
	c, fs := newTestControlWithFakeStorage(t)
	fs.failPut = true

	doc := `{"uuid":"should-not-persist","http":[]}`
	rec := serveHTTP(c, http.MethodPut, "/rules/10.0.0.40?validate=false", strings.NewReader(doc))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body)
	}

	fs.failPut = false
	getRec := serveHTTP(c, http.MethodGet, "/rules/10.0.0.40", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{"http":[]}` {
		t.Fatalf("GET after failed save = %s, want the unwritten default (not %q)", got, doc)
	}
}

// TestControl_HandlePutDefaultStorageSaveFails mirrors
// TestControl_HandlePutRuleStorageSaveFails for PUT /rules/default's
// SaveDefault call.
func TestControl_HandlePutDefaultStorageSaveFails(t *testing.T) {
	c, fs := newTestControlWithFakeStorage(t)
	fs.failPut = true

	doc := `{"0.0.0.0/0":{"uuid":"should-not-persist","http":[]},"::/0":{"http":[]}}`
	rec := serveHTTP(c, http.MethodPut, "/rules/default?validate=false", strings.NewReader(doc))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body)
	}

	fs.failPut = false
	getRec := serveHTTP(c, http.MethodGet, "/rules/default", nil)
	if got := strings.TrimSpace(getRec.Body.String()); got != `{}` {
		t.Fatalf("GET after failed save = %s, want the unwritten default (not %q)", got, doc)
	}
}

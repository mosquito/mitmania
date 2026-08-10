package storage

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func newDebugLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestWithLogging_LogsEachCallAtDebug(t *testing.T) {
	var buf bytes.Buffer
	st := testStorage(t)
	logged := WithLogging(st, newDebugLogger(&buf))
	ctx := context.Background()

	if err := logged.Put(ctx, "a/b", []byte("hi")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := logged.Get(ctx, "a/b"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := logged.Stat(ctx, "a/b"); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if _, err := logged.List(ctx, "a/"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if err := logged.Delete(ctx, "a/b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := logged.DeletePrefix(ctx, "a/"); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}

	out := buf.String()
	for _, op := range []string{"op=put", "op=get", "op=stat", "op=list", "op=delete", "op=delete_prefix"} {
		if !strings.Contains(out, op) {
			t.Errorf("log output missing %q; got:\n%s", op, out)
		}
	}
}

func TestWithLogging_PreservesLinkerCapability(t *testing.T) {
	var buf bytes.Buffer
	st := testStorage(t) // *PosixStorage implements Linker
	logged := WithLogging(st, newDebugLogger(&buf))

	linker, ok := logged.(Linker)
	if !ok {
		t.Fatalf("WithLogging wrapping a Linker-capable backend lost the Linker capability")
	}

	ctx := context.Background()
	if err := logged.Put(ctx, "certs/x", []byte("data")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := linker.Symlink(ctx, "names/x", "certs/x"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if !strings.Contains(buf.String(), "op=symlink") {
		t.Errorf("Symlink call was not logged; got:\n%s", buf.String())
	}
}

func TestWithLogging_NonLinkerBackendStaysNonLinker(t *testing.T) {
	logged := WithLogging(&nonLinkerStub{}, newDebugLogger(&bytes.Buffer{}))
	if _, ok := logged.(Linker); ok {
		t.Fatalf("WithLogging gave a non-Linker backend the Linker capability")
	}
}

// nonLinkerStub is a minimal Storage that does NOT implement Linker,
// standing in for S3Storage without needing a real S3 endpoint.
type nonLinkerStub struct{}

func (nonLinkerStub) Get(context.Context, string) ([]byte, Version, error) {
	return nil, "", ErrNotExist
}
func (nonLinkerStub) Put(context.Context, string, []byte) error     { return nil }
func (nonLinkerStub) Delete(context.Context, string) error          { return nil }
func (nonLinkerStub) DeletePrefix(context.Context, string) error    { return nil }
func (nonLinkerStub) Stat(context.Context, string) (Version, error) { return "", ErrNotExist }
func (nonLinkerStub) List(context.Context, string) ([]Entry, error) { return nil, nil }

func testStorage(t *testing.T) *PosixStorage {
	t.Helper()
	st, err := NewPosixStorage(t.TempDir())
	if err != nil {
		t.Fatalf("NewPosixStorage: %v", err)
	}
	return st
}

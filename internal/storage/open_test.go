package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_PosixAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	st, err := Open("posix://" + dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := st.(*PosixStorage); !ok {
		t.Fatalf("Open(posix://...) returned %T, want *PosixStorage", st)
	}
}

func TestOpen_PosixTildeExpandsToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	st, err := Open("posix://~/mitmania")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p, ok := st.(*PosixStorage)
	if !ok {
		t.Fatalf("Open(posix://~/...) returned %T, want *PosixStorage", st)
	}
	if want := filepath.Join(home, "mitmania"); p.root != want {
		t.Fatalf("root = %q, want %q", p.root, want)
	}
}

func TestOpen_PosixRelativePath(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(wd) })

	st, err := Open("posix://./sub/dir")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	p, ok := st.(*PosixStorage)
	if !ok {
		t.Fatalf("Open(posix://./...) returned %T, want *PosixStorage", st)
	}
	if want := "./sub/dir"; p.root != want {
		t.Fatalf("root = %q, want %q", p.root, want)
	}
	if _, err := os.Stat(filepath.Join(tmp, "sub", "dir")); err != nil {
		t.Fatalf("relative posix:// path was not created under cwd: %v", err)
	}
}

func TestOpen_UnsupportedScheme(t *testing.T) {
	if _, err := Open("redis://localhost/0"); err == nil {
		t.Fatalf("Open(redis://...): expected error, got nil")
	}
}

func TestOpen_S3MissingBucket(t *testing.T) {
	if _, err := Open("s3://key:secret@localhost/"); err == nil {
		t.Fatalf("Open(s3://... without bucket): expected error, got nil")
	}
}

func TestOpen_S3MissingCredentials(t *testing.T) {
	if _, err := Open("s3://localhost/?bucket=x"); err == nil {
		t.Fatalf("Open(s3://... without credentials): expected error, got nil")
	}
}

func TestOpen_S3Valid(t *testing.T) {
	st, err := Open("s3://key:secret@localhost:9000/?bucket=mitmania&region=us-east-1&secure=false")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := st.(*S3Storage); !ok {
		t.Fatalf("Open(s3://...) returned %T, want *S3Storage", st)
	}
}

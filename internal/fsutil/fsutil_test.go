package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "file.txt")

	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want hello", got)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("dir has %d entries after write, want 1 (no leftover tmp file): %v", len(entries), entries)
	}

	if err := WriteFileAtomic(path, []byte("overwritten"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic (overwrite): %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "overwritten" {
		t.Fatalf("content = %q, want overwritten", got)
	}
}

func TestSymlinkAtomic(t *testing.T) {
	dir := t.TempDir()
	target := "by-id/abc.p12"
	link := filepath.Join(dir, "leaf", "example.com.p12")

	if err := SymlinkAtomic(target, link); err != nil {
		t.Fatalf("SymlinkAtomic: %v", err)
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != target {
		t.Fatalf("link target = %q, want %q", got, target)
	}

	// Replacing an existing symlink must succeed (os.Symlink alone would
	// fail with "file exists").
	newTarget := "by-id/def.p12"
	if err := SymlinkAtomic(newTarget, link); err != nil {
		t.Fatalf("SymlinkAtomic (replace): %v", err)
	}
	got, err = os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	if got != newTarget {
		t.Fatalf("link target after replace = %q, want %q", got, newTarget)
	}
}

package storage

import (
	"context"
	"errors"
	"os"
	"testing"
)

// testPrefix namespaces every key these tests touch, so a shared/long-lived
// mock bucket never accumulates keys that collide with real usage.
const testPrefix = "mitmania-storage-test/"

// openS3OrSkip opens the Storage backend named by $S3_URL (e.g.
// "s3://KEY:SECRET@127.0.0.1:9000/?bucket=mitmania-test&secure=false"),
// skipping the test entirely when it's unset. These tests need a real,
// already-running S3-compatible server (MinIO, s3mock, ...) reachable at
// that URL and with its bucket already created — nothing here starts one
// or provisions the bucket; that's the operator's responsibility (e.g.
// running an s3mock container and exporting S3_URL before `go test`).
func openS3OrSkip(t *testing.T) Storage {
	t.Helper()
	raw := os.Getenv("S3_URL")
	if raw == "" {
		t.Skip("S3_URL not set; skipping S3 integration test")
	}
	s, err := Open(raw)
	if err != nil {
		t.Fatalf("Open(%q): %v", raw, err)
	}
	return s
}

func TestS3Storage_PutGetRoundTrip(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	key := testPrefix + "roundtrip"
	want := []byte("hello s3")

	if err := s.Put(ctx, key, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() { s.Delete(ctx, key) })

	got, ver, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("Get = %q, want %q", got, want)
	}
	if ver == "" {
		t.Errorf("Version is empty")
	}
}

func TestS3Storage_GetMissingKeyReturnsErrNotExist(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()

	_, _, err := s.Get(ctx, testPrefix+"does-not-exist")
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("Get missing key: err = %v, want ErrNotExist", err)
	}
}

func TestS3Storage_StatMatchesGetVersion(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	key := testPrefix + "stat-matches-get"

	if err := s.Put(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() { s.Delete(ctx, key) })

	_, getVer, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	statVer, err := s.Stat(ctx, key)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if statVer != getVer {
		t.Errorf("Stat Version = %q, want %q (from Get)", statVer, getVer)
	}
}

func TestS3Storage_StatMissingKeyReturnsErrNotExist(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()

	_, err := s.Stat(ctx, testPrefix+"does-not-exist")
	if !errors.Is(err, ErrNotExist) {
		t.Fatalf("Stat missing key: err = %v, want ErrNotExist", err)
	}
}

func TestS3Storage_PutOverwriteChangesVersion(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	key := testPrefix + "overwrite"

	if err := s.Put(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	t.Cleanup(func() { s.Delete(ctx, key) })
	_, ver1, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get v1: %v", err)
	}

	if err := s.Put(ctx, key, []byte("v2, different content and length")); err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	got, ver2, err := s.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get v2: %v", err)
	}
	if string(got) != "v2, different content and length" {
		t.Errorf("Get after overwrite = %q, want the v2 content", got)
	}
	if ver1 == ver2 {
		t.Errorf("Version unchanged across an overwrite with different content: %q", ver1)
	}
}

func TestS3Storage_DeleteRemovesKey(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	key := testPrefix + "delete-me"

	if err := s.Put(ctx, key, []byte("gone soon")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := s.Get(ctx, key); !errors.Is(err, ErrNotExist) {
		t.Fatalf("Get after Delete: err = %v, want ErrNotExist", err)
	}
}

func TestS3Storage_DeleteMissingKeyIsNotError(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()

	if err := s.Delete(ctx, testPrefix+"never-existed"); err != nil {
		t.Fatalf("Delete on a missing key returned an error, want nil: %v", err)
	}
}

func TestS3Storage_ListReturnsKeysUnderPrefix(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	prefix := testPrefix + "list/"
	keys := []string{prefix + "a", prefix + "b", prefix + "c"}

	for _, k := range keys {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	t.Cleanup(func() { s.DeletePrefix(ctx, prefix) })

	entries, err := s.List(ctx, prefix)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		if e.Version == "" {
			t.Errorf("entry %s has an empty Version", e.Key)
		}
		got[e.Key] = true
	}
	for _, k := range keys {
		if !got[k] {
			t.Errorf("List(%q) missing key %s; got %v", prefix, k, entries)
		}
	}
}

func TestS3Storage_DeletePrefixRemovesAllMatchingKeys(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()
	prefix := testPrefix + "delete-prefix/"
	keys := []string{prefix + "a", prefix + "b", prefix + "nested/c"}

	for _, k := range keys {
		if err := s.Put(ctx, k, []byte("x")); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}

	if err := s.DeletePrefix(ctx, prefix); err != nil {
		t.Fatalf("DeletePrefix: %v", err)
	}

	entries, err := s.List(ctx, prefix)
	if err != nil {
		t.Fatalf("List after DeletePrefix: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("List(%q) after DeletePrefix = %v, want empty", prefix, entries)
	}
	for _, k := range keys {
		if _, _, err := s.Get(ctx, k); !errors.Is(err, ErrNotExist) {
			t.Errorf("Get(%s) after DeletePrefix: err = %v, want ErrNotExist", k, err)
		}
	}
}

func TestS3Storage_DeletePrefixMissingPrefixIsNotError(t *testing.T) {
	s := openS3OrSkip(t)
	ctx := context.Background()

	if err := s.DeletePrefix(ctx, testPrefix+"nothing-here/"); err != nil {
		t.Fatalf("DeletePrefix on a matchless prefix returned an error, want nil: %v", err)
	}
}

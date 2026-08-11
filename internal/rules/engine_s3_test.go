package rules

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"mitmania/internal/storage"
)

// openTestS3OrSkip opens the Storage backend named by $S3_URL, skipping
// the test entirely when it's unset — mirrors
// internal/storage.openS3OrSkip. Needs a real, already-running
// S3-compatible server (MinIO, s3mock, ...) reachable at that URL with
// its bucket already created.
func openTestS3OrSkip(t *testing.T) storage.Storage {
	t.Helper()
	raw := os.Getenv("S3_URL")
	if raw == "" {
		t.Skip("S3_URL not set; skipping S3 integration test")
	}
	s, err := storage.Open(raw)
	if err != nil {
		t.Fatalf("Open(%q): %v", raw, err)
	}
	return s
}

// TestRuleEngine_Lookup_ConvergesAcrossIndependentNodes_S3 is
// TestRuleEngine_Lookup_ConvergesAcrossIndependentNodes against a real
// S3-compatible backend instead of posix — the distributed-operation
// claim only means something in production against the backend real
// fleets actually share (S3), so it's worth proving independently of
// posix's simpler, single-filesystem semantics (e.g. S3's read-after-write
// consistency, its own version/ETag scheme via Storage.Stat).
func TestRuleEngine_Lookup_ConvergesAcrossIndependentNodes_S3(t *testing.T) {
	ctx := context.Background()
	client := netip.MustParseAddr("203.0.113.10")

	// Two independent Storage clients against the SAME bucket — exactly
	// as two real node processes pointed at the same s3:// URL would
	// each open their own client.
	storeA := NewRuleStore(openTestS3OrSkip(t))
	storeB := NewRuleStore(openTestS3OrSkip(t))
	engineA := NewRuleEngine(storeA)
	engineB := NewRuleEngine(storeB)

	t.Cleanup(func() { storeA.Delete(ctx, client) })

	rsB, err := engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 0 {
		t.Fatalf("initial rules on node B = %d, want 0", len(rsB.rules))
	}

	// Node A alone receives the write; node B's store/engine never
	// touch it.
	if err := storeA.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rsB, err = engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 1 {
		t.Fatalf("rules on node B after node A's write = %d, want 1", len(rsB.rules))
	}

	// Node A revokes; node B converges on the revocation too.
	if err := storeA.Save(ctx, client, []byte(`{"http":[]}`)); err != nil {
		t.Fatal(err)
	}
	rsB, err = engineB.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsB.rules) != 0 {
		t.Fatalf("rules on node B after node A's revoke = %d, want 0", len(rsB.rules))
	}

	// Confirm symmetry, not just A -> B.
	if err := storeB.Save(ctx, client, []byte(`{"http":[{"match":{}}]}`)); err != nil {
		t.Fatal(err)
	}
	rsA, err := engineA.Lookup(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(rsA.rules) != 1 {
		t.Fatalf("rules on node A after node B's write = %d, want 1", len(rsA.rules))
	}
}

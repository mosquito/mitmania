package proxy

import "testing"

// TestCopyBufPool_ReusesBackingArray proves putCopyBuf/getCopyBuf actually
// hand back the same 32KiB buffer rather than each call minting a fresh
// one — the whole point of pooling relay()'s io.Copy scratch space instead
// of letting every tunnel allocate (and, once idle, leave to GC/the
// runtime's own page-release schedule) its own.
func TestCopyBufPool_ReusesBackingArray(t *testing.T) {
	b1 := getCopyBuf()
	if len(*b1) != copyBufSize {
		t.Fatalf("len = %d, want %d", len(*b1), copyBufSize)
	}
	putCopyBuf(b1)

	b2 := getCopyBuf()
	defer putCopyBuf(b2)
	if &(*b1)[0] != &(*b2)[0] {
		t.Fatalf("getCopyBuf after putCopyBuf returned a different backing array — pool did not reuse the buffer")
	}
}

// TestCopyBufPool_SteadyStateAllocsPerGetPut proves a get/put round trip
// costs (near) zero allocations once the pool is warm — the get-copy-put
// pattern every relay()/handleH2Stream call site follows.
func TestCopyBufPool_SteadyStateAllocsPerGetPut(t *testing.T) {
	putCopyBuf(getCopyBuf()) // warm the pool before measuring steady state

	allocs := testing.AllocsPerRun(1000, func() {
		buf := getCopyBuf()
		putCopyBuf(buf)
	})
	if allocs > 0 {
		t.Fatalf("getCopyBuf/putCopyBuf allocated %.1f times per call on average, want 0 (steady-state reuse)", allocs)
	}
}

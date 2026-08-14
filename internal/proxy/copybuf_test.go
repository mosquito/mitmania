package proxy

import "testing"

// TestCopyBufPool_SteadyStateAllocsPerGetPut proves a get/put round trip
// costs (near) zero allocations once the pool is warm — the get-copy-put
// pattern every relay()/handleH2Stream call site follows. This is measured
// as amortized allocations over many iterations, not "Get after Put
// returns the identical object": sync.Pool makes no such per-call
// guarantee even in a single goroutine with no other user of the pool —
// Put can land in the current P's private slot, and Go's async preemption
// can migrate the goroutine to a different P before the next Get, which
// then misses that slot (it isn't stealable) and falls through to New.
// Uses a private pool instance, not the package-level copyBufPool: that
// global is shared with every other test in this package that exercises
// relay()/handleH2Stream, including background goroutines from an earlier
// test still finishing I/O concurrently with this one.
func TestCopyBufPool_SteadyStateAllocsPerGetPut(t *testing.T) {
	pool := newCopyBufPool()
	pool.Put(pool.Get()) // warm the pool before measuring steady state

	allocs := testing.AllocsPerRun(1000, func() {
		buf := pool.Get()
		pool.Put(buf)
	})
	// A small margin, not 0: an occasional preemption-induced pool miss
	// (see above) costs one extra New() without indicating pooling is
	// broken. A implementation that isn't pooling at all averages ~1
	// alloc/call, an order of magnitude above this margin.
	if allocs > 0.05 {
		t.Fatalf("Get/Put allocated %.3f times per call on average, want near-zero (steady-state reuse)", allocs)
	}
}

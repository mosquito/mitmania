package proxy

import "testing"

// TestCopyBufPool_SteadyStateAllocsPerGetPut checks amortized allocations,
// not object identity: sync.Pool doesn't guarantee Get returns what Put
// just stored, even single-goroutine (a Put can land in the calling P's
// private slot, and async preemption can move the goroutine to another P
// before the next Get). Uses a private pool, not the shared copyBufPool,
// which every other test in this package also exercises concurrently.
func TestCopyBufPool_SteadyStateAllocsPerGetPut(t *testing.T) {
	pool := newCopyBufPool()
	pool.Put(pool.Get()) // warm up

	allocs := testing.AllocsPerRun(1000, func() {
		pool.Put(pool.Get())
	})
	// Small margin, not 0: an occasional preemption-induced miss costs one
	// extra New() without meaning pooling is broken. No pooling at all
	// would average ~1 alloc/call, an order of magnitude above this.
	if allocs > 0.05 {
		t.Fatalf("Get/Put allocated %.3f times per call on average, want near-zero", allocs)
	}
}

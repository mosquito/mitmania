package proxy

import "sync"

// copyBufSize matches io.Copy's own default scratch-buffer size, so
// pooling changes only where the buffer comes from, not how a copy chunks.
const copyBufSize = 32 * 1024

// newCopyBufPool is factored out from copyBufPool so tests can use a
// private instance instead of racing the shared, process-wide one.
func newCopyBufPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			b := make([]byte, copyBufSize)
			return &b
		},
	}
}

// copyBufPool lets relay() and handleH2Stream reuse io.Copy scratch
// buffers instead of each call allocating its own. Values are *[]byte,
// passed through unchanged by getCopyBuf/putCopyBuf — Put-ing a fresh &b
// each call would allocate a pointer wrapper every time.
var copyBufPool = newCopyBufPool()

func getCopyBuf() *[]byte {
	return copyBufPool.Get().(*[]byte)
}

func putCopyBuf(b *[]byte) {
	copyBufPool.Put(b)
}

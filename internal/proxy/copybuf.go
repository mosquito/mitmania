package proxy

import "sync"

// copyBufSize matches io.Copy's own default scratch-buffer size (see the
// unexported io.copyBuffer), so pooling changes only where the buffer comes
// from, never how a copy is chunked.
const copyBufSize = 32 * 1024

// copyBufPool lets relay() and handleH2Stream's response-body copy reuse
// one process-wide set of io.Copy scratch buffers instead of every
// concurrent tunnel/response allocating (and, once idle, leaving GC and the
// runtime's own page-release schedule to eventually reclaim) its own fresh
// 32KiB buffer. Pool values are *[]byte, and getCopyBuf/putCopyBuf pass that
// same pointer through unchanged end to end — boxing a fresh &b on every
// putCopyBuf call (as a naive []byte-in, take-its-address-out pair would)
// would still allocate a small pointer wrapper on every single call, right
// back to the kind of per-call garbage this pool exists to avoid.
var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

func getCopyBuf() *[]byte {
	return copyBufPool.Get().(*[]byte)
}

func putCopyBuf(b *[]byte) {
	copyBufPool.Put(b)
}

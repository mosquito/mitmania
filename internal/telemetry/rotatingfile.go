package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// rotatingFile is an append-only JSONL sink that rotates to a fresh file
// once the current one exceeds maxSize bytes or maxAge age
// (--otel-spool-max-size/--otel-spool-max-age) — a plain local
// directory, deliberately NOT the same Storage abstraction used for
// durable state elsewhere in this codebase: telemetry is high-volume
// append-and-rotate, Storage is atomic whole-blob replace, the wrong
// access pattern for this. Shipping a rotated file onward (including to
// S3) is the external shipper's job, not this type's.
type rotatingFile struct {
	dir     string
	maxSize int64
	maxAge  time.Duration

	mu     sync.Mutex
	f      *os.File
	size   int64
	opened time.Time
}

func newRotatingFile(dir string, maxSize int, maxAge time.Duration) (*rotatingFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("telemetry: spool dir %s: %w", dir, err)
	}
	rf := &rotatingFile{dir: dir, maxSize: int64(maxSize), maxAge: maxAge}
	if err := rf.rotate(); err != nil {
		return nil, err
	}
	return rf, nil
}

// WriteLine appends line plus a trailing newline, rotating first if the
// current file has already hit its size or age limit — checked before
// the write, not after, so a single oversized line never leaves the
// current file more than one line past the limit but the NEXT write
// always lands in a fresh file once the limit is crossed.
func (rf *rotatingFile) WriteLine(line []byte) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.size >= rf.maxSize || time.Since(rf.opened) >= rf.maxAge {
		if err := rf.rotate(); err != nil {
			return err
		}
	}
	n, err := rf.f.Write(append(line, '\n'))
	rf.size += int64(n)
	if err != nil {
		return fmt.Errorf("telemetry: write spool line: %w", err)
	}
	return nil
}

func (rf *rotatingFile) rotate() error {
	if rf.f != nil {
		rf.f.Close()
	}
	name := fmt.Sprintf("otel-traces-%s.jsonl", time.Now().UTC().Format("20060102T150405.000000000Z"))
	f, err := os.OpenFile(filepath.Join(rf.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("telemetry: open spool file: %w", err)
	}
	rf.f = f
	rf.size = 0
	rf.opened = time.Now()
	return nil
}

func (rf *rotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.f == nil {
		return nil
	}
	err := rf.f.Close()
	rf.f = nil
	return err
}

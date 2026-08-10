// Package storage implements mitmania's pluggable state backend: a
// flat, content-addressed blob store keyed by "/"-delimited logical
// paths. Every persisted thing — the root CA, leaf cert cache entries,
// and per-client rule files — goes through the Storage interface here,
// never touching a filesystem or bucket API directly outside its one
// backend implementation.
package storage

import (
	"context"
	"errors"
)

// ErrNotExist is returned by Get and Stat when key has no value.
var ErrNotExist = errors.New("storage: key does not exist")

// Version is an opaque, backend-specific change token: PosixStorage
// encodes mtime+size, an S3-style backend would use the object's ETag.
// The only contract callers may rely on is that two reads of the same
// key return equal Versions iff nothing changed between them — the
// encoding itself is never interpreted outside the backend that produced
// it.
type Version string

// Entry is one result from List.
type Entry struct {
	Key     string
	Version Version
}

// Storage is mitmania's pluggable state backend. Keys are
// "/"-delimited logical paths (e.g. "leaf/certs/ab/cd/ef/...", "ca/ca.p12",
// "rules/<sha1>.json"); how a backend maps that to its own storage model
// (nested directories, a flat bucket namespace, table rows) is entirely
// its own concern below this interface.
type Storage interface {
	// Get returns key's current value and Version. ErrNotExist on miss.
	Get(ctx context.Context, key string) ([]byte, Version, error)
	// Put atomically replaces key's value, creating it if absent.
	Put(ctx context.Context, key string, data []byte) error
	// Delete removes key. Not an error if key is already absent.
	Delete(ctx context.Context, key string) error
	// DeletePrefix removes every key beginning with prefix (e.g. wiping
	// "leaf/" wholesale on a cluster-key change). Not an error if
	// nothing matches.
	DeletePrefix(ctx context.Context, prefix string) error
	// Stat returns key's current Version without fetching its value —
	// the change-detection primitive the rule engine polls to hot-reload
	// a rule file when its Storage key changes. ErrNotExist on miss.
	Stat(ctx context.Context, key string) (Version, error)
	// List returns every key beginning with prefix. For operator
	// browsing/sweeps (e.g. counting cached certs for /stats) — never on
	// the request-serving path.
	List(ctx context.Context, prefix string) ([]Entry, error)
}

// Linker is an optional Storage capability: a small alias pointing one
// key at another's current content, without duplicating it. It backs the
// leaf cache's names/ operator index — never on the serving path,
// so a backend that doesn't implement Linker simply doesn't get that
// index rather than needing to emulate it. PosixStorage implements this
// as a real symlink; a backend without an equivalent primitive (S3) can
// leave it unimplemented.
type Linker interface {
	// Symlink makes key resolve to targetKey's content. Both are Storage
	// keys, not filesystem paths.
	Symlink(ctx context.Context, key, targetKey string) error
}

package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"mitmania/internal/fsutil"
)

// PosixStorage is the default Storage backend: every key maps
// directly to a path under root, its "/"-delimited segments becoming
// nested directories — the same on-disk layout mitmania used before
// Storage existed.
type PosixStorage struct {
	root string
}

// NewPosixStorage opens (creating if necessary) a POSIX filesystem
// Storage rooted at root.
func NewPosixStorage(root string) (*PosixStorage, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("storage: posix: create %s: %w", root, err)
	}
	return &PosixStorage{root: root}, nil
}

func (p *PosixStorage) path(key string) string {
	return filepath.Join(p.root, filepath.FromSlash(key))
}

func (p *PosixStorage) Get(ctx context.Context, key string) ([]byte, Version, error) {
	path := p.path(key)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotExist
	}
	if err != nil {
		return nil, "", fmt.Errorf("storage: posix: read %s: %w", key, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("storage: posix: stat %s: %w", key, err)
	}
	return data, versionOf(info), nil
}

func (p *PosixStorage) Put(ctx context.Context, key string, data []byte) error {
	if err := fsutil.WriteFileAtomic(p.path(key), data, 0o600); err != nil {
		return fmt.Errorf("storage: posix: write %s: %w", key, err)
	}
	return nil
}

func (p *PosixStorage) Delete(ctx context.Context, key string) error {
	if err := os.Remove(p.path(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: posix: delete %s: %w", key, err)
	}
	return nil
}

func (p *PosixStorage) DeletePrefix(ctx context.Context, prefix string) error {
	if err := os.RemoveAll(p.path(prefix)); err != nil {
		return fmt.Errorf("storage: posix: delete prefix %s: %w", prefix, err)
	}
	return nil
}

func (p *PosixStorage) Stat(ctx context.Context, key string) (Version, error) {
	info, err := os.Stat(p.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotExist
	}
	if err != nil {
		return "", fmt.Errorf("storage: posix: stat %s: %w", key, err)
	}
	return versionOf(info), nil
}

func (p *PosixStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	root := p.path(prefix)
	var entries []Entry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(p.root, path)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		entries = append(entries, Entry{Key: filepath.ToSlash(rel), Version: versionOf(info)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("storage: posix: list %s: %w", prefix, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries, nil
}

// Symlink implements Linker: a real filesystem symlink, relative so the
// whole storage root stays relocatable/copyable across nodes — the CA
// and cache contents are meant to be byte-identical copies distributed
// to every node, so an absolute symlink target would break on copy.
func (p *PosixStorage) Symlink(ctx context.Context, key, targetKey string) error {
	linkPath := p.path(key)
	targetPath := p.path(targetKey)
	rel, err := filepath.Rel(filepath.Dir(linkPath), targetPath)
	if err != nil {
		return fmt.Errorf("storage: posix: symlink %s: %w", key, err)
	}
	if err := fsutil.SymlinkAtomic(rel, linkPath); err != nil {
		return fmt.Errorf("storage: posix: symlink %s: %w", key, err)
	}
	return nil
}

// versionOf encodes a POSIX file's freshness fingerprint (mtime+size)
// as an opaque Version.
func versionOf(info os.FileInfo) Version {
	return Version(fmt.Sprintf("%d-%d", info.ModTime().UnixNano(), info.Size()))
}

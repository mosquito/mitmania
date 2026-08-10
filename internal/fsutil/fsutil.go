// Package fsutil provides the atomic tmp+rename file write mitmania uses
// everywhere it persists state to disk.
package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path via a temp file in the same
// directory, fsync, then rename — so a crash never leaves a partially
// written file at path.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmpName, err := randomTempName(dir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// SymlinkAtomic creates a symlink at linkPath pointing to target,
// replacing any existing file/symlink there. os.Symlink alone fails if
// linkPath already exists, so this goes through the same temp+rename
// dance as WriteFileAtomic.
func SymlinkAtomic(target, linkPath string) error {
	dir := filepath.Dir(linkPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmpName, err := randomTempName(dir)
	if err != nil {
		return err
	}
	if err := os.Symlink(target, tmpName); err != nil {
		return err
	}
	if err := os.Rename(tmpName, linkPath); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func randomTempName(dir string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, ".tmp-"+hex.EncodeToString(b[:])), nil
}

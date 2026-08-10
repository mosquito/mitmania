package storage

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Open constructs the Storage backend named by a --storage URL:
// "posix:///path" or "s3://KEY:SECRET@host/?bucket=...&region=...". Each
// scheme's own URL shape is parsed here, right next to the backend that
// interprets it — config.Parse only checks the scheme is one Open
// recognizes, so a full "wrong query param" or "missing bucket" error
// still surfaces from here, not duplicated in config.
func Open(rawURL string) (Storage, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("storage: invalid URL %q: %w", rawURL, err)
	}

	switch u.Scheme {
	case "posix":
		// url.Parse splits "posix://./relative" into Host="." Path="/relative"
		// and "posix://~/relative" into Host="~" Path="/relative";
		// concatenating them recovers the path as written (same trick
		// config.ParseAddr uses for unix://), while "posix:///abs/path"
		// (empty Host) is left as the absolute path.
		root := u.Host + u.Path
		if root == "" {
			return nil, fmt.Errorf("storage: posix: missing path in %q", rawURL)
		}
		expanded, err := expandTilde(root)
		if err != nil {
			return nil, fmt.Errorf("storage: posix: expand %q: %w", root, err)
		}
		return NewPosixStorage(expanded)
	case "s3":
		return newS3Storage(u)
	default:
		return nil, fmt.Errorf("storage: unsupported scheme %q (need posix:// or s3://)", u.Scheme)
	}
}

// expandTilde resolves a leading "~" (current user's home directory only —
// no "~user" support) the way a shell would, since Go's os/filepath never
// does this on its own.
func expandTilde(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
}

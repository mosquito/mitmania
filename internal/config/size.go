package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseSize parses a byte-count string with an optional k/m/g suffix
// (case-insensitive, e.g. "64k", "1m", "512"), as used by
// --http-header-limit and --http-body-window.
func ParseSize(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}

	mul := 1
	numPart := s
	switch s[len(s)-1] {
	case 'k', 'K':
		mul = 1 << 10
		numPart = s[:len(s)-1]
	case 'm', 'M':
		mul = 1 << 20
		numPart = s[:len(s)-1]
	case 'g', 'G':
		mul = 1 << 30
		numPart = s[:len(s)-1]
	}
	numPart = strings.TrimSpace(numPart)

	n, err := strconv.Atoi(numPart)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: negative", s)
	}
	return n * mul, nil
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"path"
	"strings"
)

// NormalizePath converts an archive/internal path to normalized slash-separated form.
// It trims spaces, accepts both "/" and "\", removes leading "./" and "/", and cleans "." segments.
func NormalizePath(raw string) string {
	raw = normalizePathForMatching(raw)
	raw = strings.TrimPrefix(raw, "/")
	raw = path.Clean("/" + raw)
	raw = strings.TrimPrefix(raw, "/")
	if raw == "." {
		return ""
	}

	return strings.TrimSuffix(raw, "/")
}

// NormalizePrefixHeader normalizes PBO "prefix" header value to "\" separators.
func NormalizePrefixHeader(raw string) string {
	normalized := NormalizePath(raw)
	if normalized == "" {
		return ""
	}

	return strings.ReplaceAll(normalized, "/", `\`)
}

// normalizePathForMatching normalizes user/input paths for matcher use.
func normalizePathForMatching(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, `\`, `/`)
	path = strings.TrimPrefix(path, "./")
	return path
}

// normalizeArchiveEntryPath converts input path to canonical archive form with "\" separators.
func normalizeArchiveEntryPath(raw string) (string, error) {
	// Fast path: path is already canonical (backslash separators, no spaces, no dot segments).
	// Common case for paths produced by filepath.Walk/filepath.Join on Windows.
	if isCanonicalArchivePath(raw) {
		return raw, nil
	}

	normalizedPath := NormalizePath(raw)
	if normalizedPath == "" {
		return "", fmt.Errorf("%w: %q", ErrInvalidEntryPath, raw)
	}

	return strings.ReplaceAll(normalizedPath, "/", `\`), nil
}

// isCanonicalArchivePath reports whether s is already in canonical PBO archive form:
// non-empty, backslash separators only, no leading or trailing backslash, no leading dot,
// no dot or double-dot segments, no whitespace.
func isCanonicalArchivePath(s string) bool {
	if len(s) == 0 || s[0] == '.' || s[0] == '\\' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' || c == '\t' || c == '\r' || c == '\n' || c == ' ' {
			return false
		}
		if c == '\\' {
			if i+1 >= len(s) {
				return false // trailing backslash
			}
			next := s[i+1]
			if next == '\\' || next == ' ' || next == '.' {
				return false // double backslash, space after separator, or dot segment
			}
		}
	}
	return true
}

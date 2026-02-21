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
	normalizedPath := NormalizePath(raw)
	if normalizedPath == "" {
		return "", fmt.Errorf("%w: %q", ErrInvalidEntryPath, raw)
	}

	return strings.ReplaceAll(normalizedPath, "/", `\`), nil
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"strings"
)

// EntryViewOptions configures a derived view of the raw archive entry list.
type EntryViewOptions struct {
	// PathPrefix keeps entries equal to this normalized path or below it.
	// With SanitizeNames, matching uses sanitized paths before collision suffixes.
	PathPrefix string `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty"`
	// MinOriginalSize keeps entries at or above this unpacked size.
	MinOriginalSize uint32 `json:"min_original_size,omitempty" yaml:"min_original_size,omitempty"`
	// MinDataSize keeps entries at or above this packed size.
	MinDataSize uint32 `json:"min_data_size,omitempty" yaml:"min_data_size,omitempty"`
	// FilterJunk drops entries that cannot be safely listed or extracted.
	FilterJunk bool `json:"filter_junk,omitempty" yaml:"filter_junk,omitempty"`
	// FilterASCIIOnly keeps entries whose raw path bytes are ASCII.
	FilterASCIIOnly bool `json:"filter_ascii_only,omitempty" yaml:"filter_ascii_only,omitempty"`
	// SanitizeControlChars rewrites control and format runes in paths.
	SanitizeControlChars bool `json:"sanitize_control_chars,omitempty" yaml:"sanitize_control_chars,omitempty"`
	// SanitizeNames rewrites paths to filesystem-safe names, including control and format runes.
	SanitizeNames bool `json:"sanitize_names,omitempty" yaml:"sanitize_names,omitempty"`
}

// applyEntryViewOptions derives a filtered or sanitized view without modifying raw entries.
func applyEntryViewOptions(entries []EntryInfo, opts EntryViewOptions) ([]EntryInfo, error) {
	if len(entries) == 0 {
		return entries, nil
	}

	normalizedPrefix := NormalizePath(opts.PathPrefix)
	sanitizedPrefix := normalizedPrefix
	if opts.SanitizeNames && normalizedPrefix != "" {
		var err error
		sanitizedPrefix, err = SanitizePath(normalizedPrefix)
		if err != nil {
			// Invalid sanitized prefixes historically produce an empty view.
			return nil, nil //nolint:nilerr
		}
		if sanitizedPrefix == "" {
			return nil, nil
		}
	}

	onlySanitizeNames := opts.SanitizeNames &&
		!opts.FilterJunk &&
		opts.MinOriginalSize == 0 &&
		opts.MinDataSize == 0 &&
		!opts.FilterASCIIOnly
	if onlySanitizeNames {
		if normalizedPrefix == "" {
			return sanitizeEntryInfoPaths(entries)
		}

		return sanitizeEntryInfoPathsWithPrefix(entries, sanitizedPrefix)
	}

	onlySanitizeControlChars := opts.SanitizeControlChars &&
		!opts.SanitizeNames &&
		!opts.FilterJunk &&
		opts.MinOriginalSize == 0 &&
		opts.MinDataSize == 0 &&
		!opts.FilterASCIIOnly &&
		normalizedPrefix == ""
	if onlySanitizeControlChars {
		return sanitizeEntryInfoControlPaths(entries)
	}

	prefixWithSlash := normalizedPrefix + "/"
	if opts.SanitizeNames {
		prefixWithSlash = sanitizedPrefix + "/"
	}

	needsView := opts.FilterJunk ||
		opts.MinOriginalSize != 0 ||
		opts.MinDataSize != 0 ||
		opts.FilterASCIIOnly ||
		normalizedPrefix != "" ||
		opts.SanitizeControlChars ||
		opts.SanitizeNames
	if !needsView {
		return entries, nil
	}

	out := make([]EntryInfo, 0, len(entries))
	var used map[string]struct{}
	var nextSuffix map[string]int

	for i := range entries {
		entry := entries[i]
		if opts.FilterJunk && isJunkEntry(entry) {
			continue
		}
		if opts.MinOriginalSize != 0 && filterOriginalSizeOrDataSize(entry) < opts.MinOriginalSize {
			continue
		}
		if opts.MinDataSize != 0 && entry.DataSize < opts.MinDataSize {
			continue
		}
		if opts.FilterASCIIOnly && !filterPathIsASCIIOnly(entry.Path) {
			continue
		}

		path := entry.Path
		if opts.SanitizeNames {
			var err error
			path, err = sanitizeEntryInfoPath(path, sanitizePathSegment)
			if err != nil {
				return nil, fmt.Errorf("sanitize path %s: %w", entry.Path, err)
			}
		} else if opts.SanitizeControlChars {
			var err error
			path, err = sanitizeEntryInfoPath(path, sanitizeControlCharPathSegment)
			if err != nil {
				return nil, fmt.Errorf("sanitize path %s: %w", entry.Path, err)
			}
		}

		if normalizedPrefix != "" {
			prefixPath := path
			if !opts.SanitizeNames {
				prefixPath = NormalizePath(entry.Path)
			}
			if prefixPath != sanitizedPrefix && !strings.HasPrefix(prefixPath, prefixWithSlash) {
				continue
			}
		}

		if opts.SanitizeControlChars || opts.SanitizeNames {
			if used == nil {
				used = make(map[string]struct{})
				nextSuffix = make(map[string]int)
			}
			var err error
			path, err = makeSanitizedPathUnique(path, used, nextSuffix)
			if err != nil {
				return nil, fmt.Errorf("sanitize path %s: %w", entry.Path, err)
			}
		}

		if opts.SanitizeNames {
			if _, err := normalizeExtractEntryPath(path); err != nil {
				return nil, fmt.Errorf("sanitize path %s: %w", entry.Path, err)
			}
		}

		entry.Path = path
		out = append(out, entry)
	}

	return out, nil
}

// filterOriginalSizeOrDataSize returns OriginalSize when present, otherwise DataSize.
func filterOriginalSizeOrDataSize(entry EntryInfo) uint32 {
	if entry.OriginalSize == 0 {
		return entry.DataSize
	}

	return entry.OriginalSize
}

// filterPathIsASCIIOnly reports whether path contains only ASCII bytes.
func filterPathIsASCIIOnly(pathValue string) bool {
	for idx := 0; idx < len(pathValue); idx++ {
		if pathValue[idx] >= 0x80 {
			return false
		}
	}

	return true
}

// isJunkEntry reports whether an entry is empty or cannot be safely extracted.
func isJunkEntry(entry EntryInfo) bool {
	if entry.DataSize == 0 || (entry.MimeType == MimeCompress && entry.OriginalSize == 0) {
		return true
	}

	_, err := normalizeExtractEntryPath(entry.Path)

	return err != nil
}

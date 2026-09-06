// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import "strings"

// EntryViewOptions configures a derived view of the raw archive entry list.
type EntryViewOptions struct {
	// PathPrefix keeps entries equal to this normalized path or below it.
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
	// SanitizeNames rewrites paths to filesystem-safe names.
	SanitizeNames bool `json:"sanitize_names,omitempty" yaml:"sanitize_names,omitempty"`
}

// applyEntryViewOptions derives a filtered or sanitized view without modifying raw entries.
func applyEntryViewOptions(entries []EntryInfo, opts EntryViewOptions) ([]EntryInfo, error) {
	if opts.FilterJunk {
		entries = filterJunkEntries(entries)
	}

	entries = filterEntriesBySize(entries, opts.MinOriginalSize, opts.MinDataSize)
	if opts.FilterASCIIOnly {
		entries = filterEntriesByASCIIOnly(entries)
	}

	if opts.SanitizeNames {
		entries = filterEntriesBySanitizedPrefix(entries, opts.PathPrefix)
	} else {
		entries = filterEntriesByPrefix(entries, opts.PathPrefix)
	}

	if opts.SanitizeControlChars {
		var err error
		entries, err = sanitizeEntryInfoControlPaths(entries)
		if err != nil {
			return nil, err
		}
	}

	if opts.SanitizeNames {
		var err error
		entries, err = sanitizeEntryInfoPaths(entries)
		if err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// filterOriginalSizeOrDataSize returns OriginalSize when present, otherwise DataSize.
func filterOriginalSizeOrDataSize(entry EntryInfo) uint32 {
	if entry.OriginalSize == 0 {
		return entry.DataSize
	}

	return entry.OriginalSize
}

// filterEntriesBySize keeps entries that satisfy min original and packed size thresholds.
func filterEntriesBySize(entries []EntryInfo, minOriginalSize uint32, minDataSize uint32) []EntryInfo {
	if minOriginalSize == 0 && minDataSize == 0 {
		return entries
	}

	out := make([]EntryInfo, 0, len(entries))
	for _, entry := range entries {
		if filterOriginalSizeOrDataSize(entry) < minOriginalSize {
			continue
		}

		if entry.DataSize < minDataSize {
			continue
		}

		out = append(out, entry)
	}

	return out
}

// filterEntriesByASCIIOnly keeps entries whose path contains only ASCII bytes.
func filterEntriesByASCIIOnly(entries []EntryInfo) []EntryInfo {
	out := make([]EntryInfo, 0, len(entries))
	for _, entry := range entries {
		if !filterPathIsASCIIOnly(entry.Path) {
			continue
		}

		out = append(out, entry)
	}

	return out
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

// filterEntriesByPrefix keeps entries under prefix (or exact match if it points to a file).
func filterEntriesByPrefix(entries []EntryInfo, prefix string) []EntryInfo {
	prefix = NormalizePath(prefix)
	if prefix == "" {
		return entries
	}

	normalizedPrefix := prefix + "/"
	out := make([]EntryInfo, 0, len(entries))
	for _, entry := range entries {
		entryPath := NormalizePath(entry.Path)
		if entryPath == prefix || strings.HasPrefix(entryPath, normalizedPrefix) {
			out = append(out, entry)
		}
	}

	return out
}

// filterEntriesBySanitizedPrefix keeps entries under prefix in sanitized path namespace.
func filterEntriesBySanitizedPrefix(entries []EntryInfo, prefix string) []EntryInfo {
	normalizedPrefix := NormalizePath(prefix)
	if normalizedPrefix == "" {
		return entries
	}

	sanitizedPrefix, err := SanitizePath(normalizedPrefix)
	if err != nil || sanitizedPrefix == "" {
		return nil
	}

	sanitizedPrefixWithSlash := sanitizedPrefix + "/"
	out := make([]EntryInfo, 0, len(entries))
	for _, entry := range entries {
		sanitizedEntryPath, sanitizeErr := SanitizePath(entry.Path)
		if sanitizeErr != nil || sanitizedEntryPath == "" {
			continue
		}

		if sanitizedEntryPath == sanitizedPrefix || strings.HasPrefix(sanitizedEntryPath, sanitizedPrefixWithSlash) {
			out = append(out, entry)
		}
	}

	return out
}

// filterJunkEntries removes malformed or unusable entries from parsed table.
func filterJunkEntries(entries []EntryInfo) []EntryInfo {
	if len(entries) == 0 {
		return entries
	}

	filtered := make([]EntryInfo, 0, len(entries))
	for i := range entries {
		entry := entries[i]
		if entry.DataSize == 0 {
			continue
		}
		if entry.MimeType == MimeCompress && entry.OriginalSize == 0 {
			continue
		}
		if _, err := normalizeExtractEntryPath(entry.Path); err != nil {
			continue
		}

		filtered = append(filtered, entry)
	}

	return filtered
}

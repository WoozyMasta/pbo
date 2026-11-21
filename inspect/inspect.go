// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import (
	"fmt"
	"path"
	"strings"
	"unicode"

	"github.com/woozymasta/pbo"
)

// Matches returns a copy of the selected records in source order.
func (s Selection) Matches() []Match {
	matches := make([]Match, len(s.entries))
	for index := range s.entries {
		diagnostic := s.probeResults[index]
		matches[index] = Match{
			SourceIndex:    s.sourceIndices[index],
			Raw:            s.entries[index],
			ProbeResult:    diagnostic.result,
			HasProbeResult: diagnostic.probed,
			TextLike:       diagnostic.textLike,
			Decoded:        diagnostic.decoded,
			RawFallback:    diagnostic.rawFallback,
			DecodeError:    diagnostic.decodeError,
			ConsumedBytes:  diagnostic.consumed,
		}
	}

	return matches
}

// Entries returns raw entry metadata suitable for pbo.ExtractOptions.Entries.
// It always returns a non-nil slice, including when the selection is empty.
func (s Selection) Entries() []pbo.EntryInfo {
	entries := make([]pbo.EntryInfo, len(s.entries))
	copy(entries, s.entries)

	return entries
}

// Statistics returns counters for the completed selection pass.
func (s Selection) Statistics() Statistics {
	return s.statistics
}

// View builds display paths after selection without changing raw match identity.
func View(selection Selection, opts ViewOptions) ([]ViewEntry, error) {
	var safeEntries []pbo.EntryInfo
	if opts.FilesystemSafe {
		// Sanitize the complete selection at once so collisions are resolved against every retained path.
		var err error
		safeEntries, err = pbo.SanitizeEntries(selection.entries)
		if err != nil {
			return nil, err
		}
	}

	view := make([]ViewEntry, len(selection.entries))
	var usedPaths map[string]struct{}
	var nextSuffix map[string]int
	if opts.ControlChars && !opts.FilesystemSafe {
		// Display-only sanitation can also collapse distinct names, so track collisions it introduces.
		usedPaths = make(map[string]struct{}, len(selection.entries))
		nextSuffix = make(map[string]int)
	}

	for index, rawEntry := range selection.entries {
		displayPath := rawEntry.Path
		switch {
		case opts.FilesystemSafe:
			// Filesystem-safe projection owns sanitation and collision handling when both modes are requested.
			displayPath = safeEntries[index].Path

		case opts.ControlChars:
			// Keep raw identity untouched; only the projected path is rewritten for display.
			displayPath = sanitizeControlPath(displayPath)
			displayPath = makeDisplayPathUnique(displayPath, usedPaths, nextSuffix)
		}

		normalizedDisplayPath := displayPath
		if !opts.FilesystemSafe && !opts.ControlChars {
			// Parent paths follow canonical separators even when the caller wants the original display spelling.
			normalizedDisplayPath = pbo.NormalizePath(displayPath)
		}

		parentPath := path.Dir(normalizedDisplayPath)
		if parentPath == "." {
			parentPath = ""
		}

		view[index] = ViewEntry{
			SourceIndex: selection.sourceIndices[index],
			Raw:         rawEntry,
			DisplayPath: displayPath,
			ParentPath:  parentPath,
		}
	}

	return view, nil
}

// isASCII reports whether all path bytes are in the ASCII range.
func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}

	return true
}

// asciiLower folds ASCII uppercase bytes without applying Unicode case folding.
func asciiLower(value string) string {
	bytes := []byte(value)
	for index, valueByte := range bytes {
		if valueByte >= 'A' && valueByte <= 'Z' {
			bytes[index] = valueByte + ('a' - 'A')
		}
	}

	return string(bytes)
}

// pathHasPrefix uses a no-allocation path for ordinary paths
// and falls back to the canonical normalizer when dot segments or redundant separators occur.
func pathHasPrefix(rawPath, prefix, prefixWithSlash string) bool {
	if isDirectlyMatchablePath(rawPath) {
		if len(rawPath) < len(prefix) {
			return false
		}

		for index := 0; index < len(prefix); index++ {
			pathByte := rawPath[index]
			prefixByte := prefix[index]
			if pathByte == '\\' {
				pathByte = '/'
			}
			if pathByte >= 'A' && pathByte <= 'Z' {
				pathByte += 'a' - 'A'
			}
			if pathByte != prefixByte {
				return false
			}
		}

		// Require a separator boundary so "foo" does not also select "foobar".
		return len(rawPath) == len(prefix) || rawPath[len(prefix)] == '/' || rawPath[len(prefix)] == '\\'
	}

	// Dot segments, roots, whitespace edges, and repeated separators need the canonical normalizer.
	normalizedPath := asciiLower(pbo.NormalizePath(rawPath))
	return normalizedPath == prefix || strings.HasPrefix(normalizedPath, prefixWithSlash)
}

// isDirectlyMatchablePath reports whether path normalization would only fold separators.
func isDirectlyMatchablePath(value string) bool {
	// These forms can change under normalization, so keep them on the canonical slow path.
	if value == "" || strings.TrimSpace(value) != value || value[0] == '/' || value[0] == '\\' {
		return false
	}

	segmentStart := 0
	for index := 0; index <= len(value); index++ {
		if index < len(value) && value[index] != '/' && value[index] != '\\' {
			continue
		}

		segment := value[segmentStart:index]
		if segment == "" || segment == "." || segment == ".." {
			// Empty and dot segments collapse or change path boundaries during normalization.
			return false
		}

		segmentStart = index + 1
	}

	return true
}

// sanitizeControlPath converts control and format runes in normalized display paths.
func sanitizeControlPath(value string) string {
	value = pbo.NormalizePath(value)
	var builder strings.Builder
	builder.Grow(len(value))

	for _, current := range value {
		if unicode.IsControl(current) || unicode.In(current, unicode.Cf) || current == '\uFFFD' {
			// Replace invisible or invalid runes so displayed paths remain legible and distinguishable.
			builder.WriteByte('_')
			continue
		}

		builder.WriteRune(current)
	}

	if builder.Len() == 0 {
		// Keep the projected path non-empty for consumers that render or index it.
		return "_"
	}

	return builder.String()
}

// makeDisplayPathUnique adds stable numeric suffixes for display collisions.
func makeDisplayPathUnique(value string, used map[string]struct{}, nextSuffix map[string]int) string {
	key := strings.ToLower(value)
	if _, exists := used[key]; !exists {
		used[key] = struct{}{}
		return value
	}

	// Continue from the last suffix assigned to this original path, avoiding repeated rescans from ~2.
	dir := path.Dir(value)
	name := path.Base(value)
	start := max(nextSuffix[key], 2)

	for suffix := start; ; suffix++ {
		// Preserve the extension while adding the smallest stable suffix that avoids a case-folded collision.
		ext := path.Ext(name)
		base := strings.TrimSuffix(name, ext)
		candidateName := fmt.Sprintf("%s~%d%s", base, suffix, ext)
		candidate := candidateName
		if dir != "." {
			candidate = path.Join(dir, candidateName)
		}

		candidateKey := strings.ToLower(candidate)
		if _, exists := used[candidateKey]; exists {
			continue
		}

		used[candidateKey] = struct{}{}
		nextSuffix[key] = suffix + 1

		return candidate
	}
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"hash/fnv"
	"path"
	"strconv"
	"strings"
)

const (
	// maxSanitizedSegmentLen limits one path segment to common filesystem-safe length.
	maxSanitizedSegmentLen = 240
)

var (
	// reservedDOSNames contains case-insensitive reserved DOS/Windows/OS2 device names.
	reservedDOSNames = map[string]struct{}{
		"$":        {},
		"$addstor": {},
		"$idle$":   {},
		"386max$$": {},
		"4dosstak": {},
		"82164a":   {},
		"aux":      {},
		"cloak$$$": {},
		"clock":    {},
		"clock$":   {},
		"com1":     {},
		"com2":     {},
		"com3":     {},
		"com4":     {},
		"com5":     {},
		"com6":     {},
		"com7":     {},
		"com8":     {},
		"com9":     {},
		"con":      {},
		"config$":  {},
		"dblssys$": {},
		"dpmixxx0": {},
		"dpmsxxx0": {},
		"emm$$$$$": {},
		"emmqxxx0": {},
		"emmxxxq0": {},
		"emmxxxx0": {},
		"hmaldsys": {},
		"ifs$hlp$": {},
		"kbd$":     {},
		"keybd$":   {},
		"lpt1":     {},
		"lpt2":     {},
		"lpt3":     {},
		"lpt4":     {},
		"lpt5":     {},
		"lpt6":     {},
		"lpt7":     {},
		"lpt8":     {},
		"lpt9":     {},
		"lst":      {},
		"mouse$":   {},
		"ndosstak": {},
		"nul":      {},
		"pc$mouse": {},
		"plt":      {},
		"pointer$": {},
		"prn":      {},
		"protman$": {},
		"qdpmi$$$": {},
		"qemm386$": {},
		"qextxxx0": {},
		"qmmxxxx0": {},
		"screen$":  {},
		"vcpixxx0": {},
		"xmsxxxx0": {},
	}
)

// sanitizeEntryInfoPaths rewrites entry paths to deterministic filesystem-safe names.
func sanitizeEntryInfoPaths(entries []EntryInfo) ([]EntryInfo, error) {
	out := make([]EntryInfo, len(entries))
	used := make(map[string]struct{}, len(entries))

	for i := range entries {
		relativePath, err := normalizeExtractEntryPath(entries[i].Path)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		sanitized, err := sanitizeRelativePath(relativePath)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		sanitized, err = makeSanitizedPathUnique(sanitized, used)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		if _, err := normalizeExtractEntryPath(sanitized); err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		out[i] = entries[i]
		out[i].Path = sanitized
	}

	return out, nil
}

// sanitizeRelativePath sanitizes each segment of relative slash-separated path.
func sanitizeRelativePath(relativePath string) (string, error) {
	parts := strings.Split(relativePath, "/")
	sanitized := make([]string, 0, len(parts))
	for _, part := range parts {
		segment, err := sanitizePathSegment(part)
		if err != nil {
			return "", err
		}

		sanitized = append(sanitized, segment)
	}

	return strings.Join(sanitized, "/"), nil
}

// sanitizePathSegment sanitizes one path segment for broad filesystem compatibility.
func sanitizePathSegment(segment string) (string, error) {
	if segment == "" {
		return "", ErrInvalidExtractPath
	}
	rawReserved := isReservedDeviceName(segment)

	var b strings.Builder
	b.Grow(len(segment))
	for _, r := range segment {
		if r < 0x20 || strings.ContainsRune(`<>:"/\|?*`, r) {
			b.WriteRune('_')
			continue
		}

		b.WriteRune(r)
	}

	sanitized := strings.TrimRight(b.String(), ". ")
	if sanitized == "" {
		sanitized = "_"
	}

	base := sanitized
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	if rawReserved || isReservedDeviceName(base) {
		sanitized = "_" + sanitized
	}

	if len(sanitized) > maxSanitizedSegmentLen {
		sanitized = shortenSegmentDeterministic(sanitized, maxSanitizedSegmentLen)
	}
	if sanitized == "" {
		return "", ErrInvalidExtractPath
	}

	return sanitized, nil
}

// isReservedDeviceName reports whether name matches reserved DOS/Windows/OS2 device identifier.
func isReservedDeviceName(name string) bool {
	candidate := strings.TrimSpace(name)
	candidate = strings.TrimRight(candidate, ". :")
	candidate = strings.ToLower(candidate)
	if dot := strings.IndexByte(candidate, '.'); dot >= 0 {
		candidate = candidate[:dot]
	}
	candidate = strings.TrimRight(candidate, ". :")
	if candidate == "" {
		return false
	}

	_, ok := reservedDOSNames[candidate]
	return ok
}

// makeSanitizedPathUnique resolves collisions by adding deterministic numeric suffix.
func makeSanitizedPathUnique(pathValue string, used map[string]struct{}) (string, error) {
	key := strings.ToLower(pathValue)
	if _, exists := used[key]; !exists {
		used[key] = struct{}{}
		return pathValue, nil
	}

	dir := path.Dir(pathValue)
	name := path.Base(pathValue)
	for idx := 2; idx < 1000000; idx++ {
		candidateName := withNumericSuffix(name, idx)
		candidate := candidateName
		if dir != "." {
			candidate = dir + "/" + candidateName
		}

		candidateKey := strings.ToLower(candidate)
		if _, exists := used[candidateKey]; exists {
			continue
		}

		used[candidateKey] = struct{}{}
		return candidate, nil
	}

	return "", ErrInvalidExtractPath
}

// withNumericSuffix appends "~N" before extension and preserves max segment length.
func withNumericSuffix(name string, n int) string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	suffix := "~" + strconv.Itoa(n)
	allowedBaseLen := max(maxSanitizedSegmentLen-len(ext)-len(suffix), 1)
	if len(base) > allowedBaseLen {
		base = shortenSegmentDeterministic(base, allowedBaseLen)
	}

	return base + suffix + ext
}

// shortenSegmentDeterministic shortens long segment while preserving deterministic identity suffix.
func shortenSegmentDeterministic(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}
	if maxLen <= 10 {
		return value[:maxLen]
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	hashPart := fmt.Sprintf("~%08x", h.Sum32())
	prefixLen := max(maxLen-len(hashPart), 1)

	return value[:prefixLen] + hashPart
}

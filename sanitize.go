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
	"unicode"
	"unicode/utf8"
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

// SanitizePath rewrites one path to deterministic filesystem-safe slash-separated form.
func SanitizePath(pathValue string) (string, error) {
	normalizedPath := NormalizePath(pathValue)
	if normalizedPath == "" {
		return "", nil
	}

	sanitized, err := sanitizeRelativePath(normalizedPath)
	if err != nil {
		return "", err
	}

	if _, err := normalizeExtractEntryPath(sanitized); err != nil {
		return "", err
	}

	return sanitized, nil
}

// sanitizeEntryInfoPaths rewrites entry paths to deterministic filesystem-safe names.
func sanitizeEntryInfoPaths(entries []EntryInfo) ([]EntryInfo, error) {
	out := make([]EntryInfo, len(entries))
	used := make(map[string]struct{}, len(entries))
	nextSuffix := make(map[string]int, len(entries))

	for i := range entries {
		sanitized, err := sanitizeEntryInfoPath(entries[i].Path, sanitizePathSegment)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		sanitized, err = makeSanitizedPathUnique(sanitized, used, nextSuffix)
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

// sanitizeEntryInfoPathsWithPrefix builds a sanitized view while filtering the same sanitized names.
func sanitizeEntryInfoPathsWithPrefix(entries []EntryInfo, prefix string) ([]EntryInfo, error) {
	prefixWithSlash := prefix + "/"
	out := make([]EntryInfo, 0)
	var used map[string]struct{}
	var nextSuffix map[string]int

	for i := range entries {
		sanitized, err := sanitizeEntryInfoPath(entries[i].Path, sanitizePathSegment)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}
		if sanitized != prefix && !strings.HasPrefix(sanitized, prefixWithSlash) {
			continue
		}

		if used == nil {
			used = make(map[string]struct{})
			nextSuffix = make(map[string]int)
		}
		sanitized, err = makeSanitizedPathUnique(sanitized, used, nextSuffix)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}
		if _, err := normalizeExtractEntryPath(sanitized); err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		entry := entries[i]
		entry.Path = sanitized
		out = append(out, entry)
	}

	return out, nil
}

// sanitizeEntryInfoControlPaths rewrites control and format runes in entry paths.
func sanitizeEntryInfoControlPaths(entries []EntryInfo) ([]EntryInfo, error) {
	out := make([]EntryInfo, len(entries))
	used := make(map[string]struct{}, len(entries))
	nextSuffix := make(map[string]int, len(entries))

	for i := range entries {
		sanitized, err := sanitizeEntryInfoPath(entries[i].Path, sanitizeControlCharPathSegment)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}
		sanitized, err = makeSanitizedPathUnique(sanitized, used, nextSuffix)
		if err != nil {
			return nil, fmt.Errorf("sanitize path %s: %w", entries[i].Path, err)
		}

		out[i] = entries[i]
		out[i].Path = sanitized
	}

	return out, nil
}

// sanitizeEntryInfoPath normalizes a raw path when safe and otherwise sanitizes its raw segments.
func sanitizeEntryInfoPath(pathValue string, sanitizeSegment func(string) (string, error)) (string, error) {
	var relativePath string
	if isCanonicalArchivePath(pathValue) && !hasWindowsAbsBackslashPrefix(pathValue) {
		relativePath = strings.ReplaceAll(pathValue, `\`, "/")
	} else if normalizedPath, err := normalizeExtractEntryPath(pathValue); err == nil {
		relativePath = normalizedPath
	} else {
		// Obfuscated names remain listable by sanitizing their segments without traversal semantics.
		relativePath = strings.ReplaceAll(pathValue, `\`, "/")
	}

	return sanitizeRelativePathWith(relativePath, sanitizeSegment)
}

// hasWindowsAbsBackslashPrefix reports drive-root paths that otherwise look canonical.
func hasWindowsAbsBackslashPrefix(pathValue string) bool {
	return len(pathValue) >= 3 && isASCIIAlpha(pathValue[0]) &&
		pathValue[1] == ':' && pathValue[2] == '\\'
}

// sanitizeRelativePath sanitizes each segment of relative slash-separated path.
func sanitizeRelativePath(relativePath string) (string, error) {
	return sanitizeRelativePathWith(relativePath, sanitizePathSegment)
}

// sanitizeRelativePathWith sanitizes each segment of relative slash-separated path with custom segment function.
func sanitizeRelativePathWith(relativePath string, sanitizeSegment func(string) (string, error)) (string, error) {
	parts := strings.Split(relativePath, "/")
	sanitized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." {
			continue
		}

		segment, err := sanitizeSegment(part)
		if err != nil {
			return "", err
		}

		sanitized = append(sanitized, segment)
	}
	if len(sanitized) == 0 {
		return "_", nil
	}

	return strings.Join(sanitized, "/"), nil
}

// sanitizePathSegment sanitizes one path segment for broad filesystem compatibility.
func sanitizePathSegment(segment string) (string, error) {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return "_", nil
	}
	segment = sanitizeWindowsGUIDSuffix(segment)
	rawReserved := isReservedDeviceName(segment)

	var b strings.Builder
	b.Grow(len(segment))
	for _, r := range segment {
		if isUnsafeControlCharRune(r) || strings.ContainsRune(`<>:"/\|?*`, r) {
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

// sanitizeControlCharPathSegment sanitizes one path segment for safe text output.
func sanitizeControlCharPathSegment(segment string) (string, error) {
	if segment == ".." {
		return "_", nil
	}

	var b strings.Builder
	b.Grow(len(segment))
	for _, r := range segment {
		if isUnsafeControlCharRune(r) {
			b.WriteRune('_')
			continue
		}

		b.WriteRune(r)
	}

	sanitized := b.String()
	if sanitized == "" {
		return "_", nil
	}

	return sanitized, nil
}

// isUnsafeControlCharRune reports whether rune is unsafe for textual output and should be replaced.
func isUnsafeControlCharRune(r rune) bool {
	if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
		return true
	}

	// U+FFFD often appears from invalid byte sequences in obfuscated names.
	return r == '\uFFFD'
}

// sanitizeWindowsGUIDSuffix rewrites trailing ".{GUID}" to avoid Windows shell namespace aliasing.
func sanitizeWindowsGUIDSuffix(segment string) string {
	dotIndex := strings.LastIndex(segment, ".{")
	if dotIndex < 0 {
		return segment
	}

	bracedGUID := segment[dotIndex+1:]
	if !isBracedGUID(bracedGUID) {
		return segment
	}

	return segment[:dotIndex] + "_" + bracedGUID
}

// isBracedGUID reports whether token matches "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}".
func isBracedGUID(token string) bool {
	if len(token) != 38 {
		return false
	}

	if token[0] != '{' || token[len(token)-1] != '}' {
		return false
	}

	// check for valid GUID format
	for idx := 1; idx < len(token)-1; idx++ {
		ch := token[idx]

		if idx == 9 || idx == 14 || idx == 19 || idx == 24 {
			if ch != '-' {
				return false
			}
			continue
		}

		if !isHex(ch) {
			return false
		}
	}

	return true
}

// isHex reports whether byte is one ASCII hexadecimal character.
func isHex(ch byte) bool {
	return (ch >= '0' && ch <= '9') ||
		(ch >= 'a' && ch <= 'f') ||
		(ch >= 'A' && ch <= 'F')
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
func makeSanitizedPathUnique(pathValue string, used map[string]struct{}, nextSuffix map[string]int) (string, error) {
	key := strings.ToLower(pathValue)
	if _, exists := used[key]; !exists {
		used[key] = struct{}{}
		return pathValue, nil
	}

	dir := path.Dir(pathValue)
	name := path.Base(pathValue)
	startIdx := 2
	if savedIdx, exists := nextSuffix[key]; exists && savedIdx > startIdx {
		startIdx = savedIdx
	}

	for idx := startIdx; idx < 1000000; idx++ {
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
		nextSuffix[key] = idx + 1
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
		prefixLen := safeUTF8PrefixLen(value, maxLen)
		if prefixLen == 0 && maxLen > 0 {
			return "_"
		}

		return value[:prefixLen]
	}

	h := fnv.New32a()
	_, _ = h.Write([]byte(value))
	hashPart := fmt.Sprintf("~%08x", h.Sum32())
	prefixLen := safeUTF8PrefixLen(value, maxLen-len(hashPart))

	return value[:prefixLen] + hashPart
}

// safeUTF8PrefixLen returns a byte limit backed up to a UTF-8 rune boundary.
func safeUTF8PrefixLen(value string, maxLen int) int {
	if maxLen <= 0 {
		return 0
	}
	if maxLen >= len(value) {
		return len(value)
	}

	for maxLen > 0 && !utf8.RuneStart(value[maxLen]) {
		maxLen--
	}

	return maxLen
}

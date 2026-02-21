// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"crypto/sha1" //nolint:gosec // Signature format requires SHA1.
	"fmt"
	"io"
	"sort"
	"strings"
)

const signHashCopyBufferSize = 32 * 1024

// ComputeHashSet calculates hash1/hash2/hash3 for a PBO.
func ComputeHashSet(path string, version SignVersion, gameType GameType) (HashSet, error) {
	var hs HashSet

	if err := validateSignHashArgs(version, gameType); err != nil {
		return hs, err
	}

	r, err := Open(path)
	if err != nil {
		return hs, err
	}
	defer func() { _ = r.Close() }()

	return computeHashSetFromReader(r, version, gameType)
}

// validateSignHashArgs validates hash/signing options.
func validateSignHashArgs(version SignVersion, gameType GameType) error {
	if version != SignVersionV2 && version != SignVersionV3 {
		return fmt.Errorf("%w: got %d", ErrUnsupportedSignVersion, version)
	}

	gameType = normalizeGameType(gameType)
	if version == SignVersionV3 && gameType != GameTypeArma && gameType != GameTypeDayZ {
		return fmt.Errorf("%w: %q", ErrUnsupportedGameTypeV3, gameType)
	}

	return nil
}

// computeHashSetFromReader calculates hash1/hash2/hash3 from parsed reader.
func computeHashSetFromReader(r *Reader, version SignVersion, gameType GameType) (HashSet, error) {
	if r == nil {
		return HashSet{}, ErrNilReader
	}

	return computeHashSetFromPackedParts(r.ra, r.size, r.hasTrailer, r.Headers(), r.entries, version, gameType)
}

// computeHashSetFromPackedParts calculates hash set from packed metadata and ReaderAt.
func computeHashSetFromPackedParts(
	ra io.ReaderAt,
	size int64,
	hasTrailer bool,
	headers []HeaderPair,
	entries []EntryInfo,
	version SignVersion,
	gameType GameType,
) (HashSet, error) {
	var hs HashSet
	if ra == nil {
		return hs, ErrNilReader
	}

	prefix := pboPrefixFromHeaders(headers)

	hash1, err := computeSignHash1(ra, size, hasTrailer)
	if err != nil {
		return hs, fmt.Errorf("hash1: %w", err)
	}

	nameHash := computeSignNameHash(entries)
	fileHash, err := computeSignFileHashFromReaderAt(ra, entries, version, gameType)
	if err != nil {
		return hs, fmt.Errorf("filehash: %w", err)
	}

	hash2 := computeSignHash2(hash1, nameHash, prefix)
	hash3 := computeSignHash3(fileHash, nameHash, prefix)

	copy(hs.Hash1[:], hash1)
	copy(hs.Hash2[:], hash2)
	copy(hs.Hash3[:], hash3)

	return hs, nil
}

// pboPrefixFromHeaders extracts the "prefix" header value from PBO metadata.
func pboPrefixFromHeaders(headers []HeaderPair) string {
	for _, h := range headers {
		if strings.EqualFold(h.Key, "prefix") {
			return h.Value
		}
	}
	return ""
}

// computeSignHash1 hashes full PBO content excluding optional 21-byte trailer.
func computeSignHash1(ra io.ReaderAt, size int64, hasTrailer bool) ([]byte, error) {
	toRead := size
	if hasTrailer && size >= 21 {
		toRead = size - 21
	}

	h := sha1.New() //nolint:gosec // Signature format requires SHA1.
	if _, err := io.Copy(h, io.NewSectionReader(ra, 0, toRead)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// writeSignPrefix appends normalized prefix fragment used by hash2/hash3.
func writeSignPrefix(h io.Writer, prefix string) {
	if prefix == "" {
		return
	}

	_, _ = h.Write([]byte(prefix))
	if !strings.HasSuffix(prefix, "\\") {
		_, _ = h.Write([]byte("\\"))
	}
}

// computeSignHash2 builds hash2 from hash1, namehash, and optional prefix.
func computeSignHash2(hash1 []byte, nameHash []byte, prefix string) []byte {
	h := sha1.New() //nolint:gosec // Signature format requires SHA1.
	_, _ = h.Write(hash1)
	_, _ = h.Write(nameHash)
	writeSignPrefix(h, prefix)
	return h.Sum(nil)
}

// computeSignHash3 builds hash3 from filehash, namehash, and optional prefix.
func computeSignHash3(fileHash []byte, nameHash []byte, prefix string) []byte {
	h := sha1.New() //nolint:gosec // Signature format requires SHA1.
	_, _ = h.Write(fileHash)
	_, _ = h.Write(nameHash)
	writeSignPrefix(h, prefix)
	return h.Sum(nil)
}

// computeSignNameHash builds deterministic SHA1 over normalized entry names.
func computeSignNameHash(entries []EntryInfo) []byte {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Path == "" || e.DataSize == 0 {
			continue
		}

		names = append(names, normalizeSignEntryName(e.Path))
	}

	sort.Strings(names)
	h := sha1.New() //nolint:gosec // Signature format requires SHA1.

	prev := ""
	for _, n := range names {
		if n == prev {
			continue
		}

		_, _ = h.Write([]byte(n))
		prev = n
	}

	return h.Sum(nil)
}

// normalizeSignEntryName normalizes entry path for namehash comparison rules.
func normalizeSignEntryName(path string) string {
	needTransform := false
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '/' || (c >= 'A' && c <= 'Z') {
			needTransform = true
			break
		}
	}

	if !needTransform {
		return path
	}

	b := []byte(path)
	for i := range b {
		if b[i] == '/' {
			b[i] = '\\'
			continue
		}

		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}

	return string(b)
}

// computeSignFileHashFromReaderAt builds deterministic SHA1 over selected packed payload bytes.
func computeSignFileHashFromReaderAt(
	ra io.ReaderAt,
	entries []EntryInfo,
	version SignVersion,
	gameType GameType,
) ([]byte, error) {
	if ra == nil {
		return nil, ErrNilReader
	}

	h := sha1.New() //nolint:gosec // Signature format requires SHA1.
	var copyBufArr [signHashCopyBufferSize]byte
	copyBuf := copyBufArr[:]

	gameType = normalizeGameType(gameType)
	hashedAny := false
	for _, e := range entries {
		if e.Path == "" || e.DataSize == 0 {
			continue
		}

		ok, err := shouldHashFileForSign(version, gameType, e.Path)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		// Filehash is computed over packed payload bytes as they are stored.
		offset := int64(e.Offset)
		remaining := int64(e.DataSize)
		for remaining > 0 {
			chunk := len(copyBuf)
			if int64(chunk) > remaining {
				chunk = int(remaining)
			}

			n, readErr := ra.ReadAt(copyBuf[:chunk], offset)
			if n > 0 {
				if _, writeErr := h.Write(copyBuf[:n]); writeErr != nil {
					return nil, fmt.Errorf("hash packed %s: %w", e.Path, writeErr)
				}

				offset += int64(n)
				remaining -= int64(n)
			}

			if readErr != nil {
				if readErr == io.EOF && remaining == 0 {
					break
				}

				return nil, fmt.Errorf("read packed %s: %w", e.Path, readErr)
			}
			if n == 0 {
				return nil, fmt.Errorf("read packed %s: %w", e.Path, io.ErrNoProgress)
			}
		}

		hashedAny = true
	}
	if !hashedAny {
		if version == SignVersionV2 {
			_, _ = h.Write([]byte("nothing"))
		} else {
			_, _ = h.Write([]byte("gnihton"))
		}
	}

	return h.Sum(nil), nil
}

// shouldHashFileForSign applies file-extension policy for v2/v3 signatures.
func shouldHashFileForSign(version SignVersion, gameType GameType, filename string) (bool, error) {
	ext := signFileExtLower(filename)
	gameType = normalizeGameType(gameType)

	switch version {
	case SignVersionV2:
		return !isV2SignExcludedExt(ext), nil

	case SignVersionV3:
		switch gameType {
		case GameTypeDayZ:
			return isDayZV3SignAllowedExt(ext), nil

		case GameTypeArma:
			return isArmaV3SignAllowedExt(ext), nil

		default:
			return false, fmt.Errorf("%w: %q", ErrUnsupportedGameTypeV3, gameType)
		}

	default:
		return false, fmt.Errorf("%w: %d", ErrUnsupportedSignVersion, version)
	}
}

// signFileExtLower extracts lower-cased ASCII extension from a path-like filename.
func signFileExtLower(filename string) string {
	sep := strings.LastIndexAny(filename, `/\`)
	dot := strings.LastIndexByte(filename, '.')
	if dot <= sep || dot+1 >= len(filename) {
		return ""
	}

	return asciiLower(filename[dot+1:])
}

// isV2SignExcludedExt reports whether extension is excluded from v2 filehash.
func isV2SignExcludedExt(ext string) bool {
	switch ext {
	case "paa", "jpg", "p3d", "tga", "rvmat", "lip", "ogg", "wss", "png", "rtm", "pac", "fxy", "wrp":
		return true
	default:
		return false
	}
}

// isDayZV3SignAllowedExt reports whether extension is included in DayZ v3 filehash.
func isDayZV3SignAllowedExt(ext string) bool {
	switch ext {
	case "bikb", "c", "ext", "hpp", "cfg", "h", "inc":
		return true
	default:
		return false
	}
}

// isArmaV3SignAllowedExt reports whether extension is included in Arma v3 filehash.
func isArmaV3SignAllowedExt(ext string) bool {
	switch ext {
	case "sqf", "inc", "bikb", "ext", "fsm", "sqm", "hpp", "cfg", "sqs", "h", "cpp":
		return true
	default:
		return false
	}
}

// asciiLower converts only ASCII A-Z to a-z and leaves all other bytes untouched.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}

			return string(b)
		}
	}

	return s
}

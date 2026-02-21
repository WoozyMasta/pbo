// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // Trailer format requires SHA1.
	"fmt"
	"io"
	"os"
)

// writeSHA1Trailer appends SHA1 trailer (0x00 + 20-byte hash) to the file.
// The hash is computed over all content up to (but not including) the trailer.
// If the file already ends with a valid trailer (0x00 followed by 20 bytes), it is replaced.
func writeSHA1Trailer(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open for trailer: %w", err)
	}
	defer func() { _ = f.Close() }()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek end: %w", err)
	}

	toHash := size
	writePos := size
	var sum []byte

	if size >= 21 {
		tail := make([]byte, 21)
		if _, err := f.ReadAt(tail, size-21); err == nil && tail[0] == 0x00 {
			candidate := size - 21
			candidateSum, err := hashFilePrefixSHA1(f, candidate)
			if err != nil {
				return fmt.Errorf("hash trailer candidate: %w", err)
			}

			if bytes.Equal(candidateSum, tail[1:21]) {
				toHash = candidate
				writePos = candidate
				sum = candidateSum
			}
		}
	}

	if sum == nil {
		computedSum, err := hashFilePrefixSHA1(f, toHash)
		if err != nil {
			return fmt.Errorf("hash content: %w", err)
		}

		sum = computedSum
		writePos = size
	}

	if _, err := f.Seek(writePos, io.SeekStart); err != nil {
		return fmt.Errorf("seek for trailer write: %w", err)
	}

	if _, err := f.Write([]byte{0x00}); err != nil {
		return fmt.Errorf("write trailer null: %w", err)
	}
	if _, err := f.Write(sum); err != nil {
		return fmt.Errorf("write trailer hash: %w", err)
	}

	return f.Sync()
}

// hashFilePrefixSHA1 calculates SHA1 over first n bytes of file.
func hashFilePrefixSHA1(f *os.File, n int64) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek start: %w", err)
	}

	h := sha1.New() //nolint:gosec // Trailer format requires SHA1.
	if _, err := io.Copy(h, io.LimitReader(f, n)); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

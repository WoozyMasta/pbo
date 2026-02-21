// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"io"
	"math"

	"github.com/woozymasta/lzss"
)

// nopCloser wraps a reader and provides a no-op close.
type nopCloser struct {
	io.Reader
}

// Close closes nopCloser (no-op).
func (nopCloser) Close() error {
	return nil
}

// findEntryByName resolves one entry by normalized path.
func (r *Reader) findEntryByName(name string) *EntryInfo {
	lookupName := NormalizePath(name)
	for i := range r.entries {
		if NormalizePath(r.entries[i].Path) == lookupName {
			return &r.entries[i]
		}
	}

	return nil
}

// openEntryByInfo opens payload stream for already resolved entry metadata.
func (r *Reader) openEntryByInfo(info *EntryInfo, name string) (io.ReadCloser, error) {
	if info == nil {
		return nil, fmt.Errorf("%w: %s", ErrEntryNotFound, name)
	}

	sr := io.NewSectionReader(r.ra, int64(info.Offset), int64(info.DataSize))
	if !info.IsCompressed() {
		return nopCloser{Reader: sr}, nil
	}

	outLen, err := checkedUint32ToInt(info.OriginalSize)
	if err != nil {
		return nil, fmt.Errorf("resolve output size for %s: %w", name, err)
	}

	pr, pw := io.Pipe()
	go streamDecompressEntry(name, pw, sr, outLen)

	return pr, nil
}

// OpenEntry opens named entry for reading.
// Returned stream yields decompressed content for LZSS-compressed entries.
func (r *Reader) OpenEntry(name string) (io.ReadCloser, error) {
	if r == nil || r.ra == nil {
		return nil, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	return r.openEntryByInfo(r.findEntryByName(name), name)
}

// OpenEntryInfo opens entry stream by already resolved metadata.
// Returned stream yields decompressed content for LZSS-compressed entries.
func (r *Reader) OpenEntryInfo(info EntryInfo) (io.ReadCloser, error) {
	if r == nil || r.ra == nil {
		return nil, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	name := info.Path
	if name == "" {
		name = "<unknown>"
	}

	return r.openEntryByInfo(&info, name)
}

// ReadEntry reads full (decompressed) content of the named entry.
func (r *Reader) ReadEntry(name string) ([]byte, error) {
	rc, err := r.OpenEntry(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	return io.ReadAll(rc)
}

// streamDecompressEntry decodes one compressed entry stream into pipe writer.
func streamDecompressEntry(name string, dst *io.PipeWriter, src io.Reader, outLen int) {
	_, err := lzss.DecompressToWriter(dst, src, outLen, nil)
	if err != nil {
		_ = dst.CloseWithError(fmt.Errorf("decompress entry %s: %w", name, err))
		return
	}

	_ = dst.Close()
}

// checkedUint32ToInt converts uint32 to int with platform-safe overflow check.
func checkedUint32ToInt(v uint32) (int, error) {
	if uint64(v) > uint64(math.MaxInt) {
		return 0, ErrSizeOverflow
	}

	return int(v), nil
}

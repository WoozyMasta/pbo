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

// maxBufferedCompressedCopySize keeps small-entry copies below one LZSS history window.
const maxBufferedCompressedCopySize = lzss.WindowSize

// nopCloser wraps a reader and provides a no-op close.
type nopCloser struct {
	io.Reader
}

// Close closes nopCloser (no-op).
func (nopCloser) Close() error {
	return nil
}

// findEntryByName resolves one raw archive entry by normalized, ASCII-folded path.
func (r *Reader) findEntryByName(name string) *EntryInfo {
	lookupName := archiveLookupKey(name)
	r.entryIndexOnce.Do(r.buildEntryIndex)

	idx, ok := r.entryIndex[lookupName]
	if !ok {
		return nil
	}

	return &r.entries[idx]
}

// buildEntryIndex builds the archive identity index for raw parsed entries.
func (r *Reader) buildEntryIndex() {
	index := make(map[string]int, len(r.entries))
	for i := range r.entries {
		key := archiveLookupKey(r.entries[i].Path)
		if _, exists := index[key]; exists {
			continue
		}

		index[key] = i
	}

	r.entryIndex = index
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
	if r == nil || r.ra == nil {
		return nil, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	info := r.findEntryByName(name)
	if info == nil {
		return nil, fmt.Errorf("%w: %s", ErrEntryNotFound, name)
	}

	return r.readEntryByInfo(info, name)
}

// readEntryByInfo reads one complete entry into a size-bounded memory buffer.
func (r *Reader) readEntryByInfo(info *EntryInfo, name string) ([]byte, error) {
	sr := io.NewSectionReader(r.ra, int64(info.Offset), int64(info.DataSize))
	if !info.IsCompressed() {
		outLen, err := checkedUint32ToInt(info.DataSize)
		if err != nil {
			return nil, fmt.Errorf("resolve input size for %s: %w", name, err)
		}

		data := make([]byte, outLen)
		if _, err := io.ReadFull(sr, data); err != nil {
			return nil, fmt.Errorf("read entry %s: %w", name, err)
		}

		return data, nil
	}

	outLen, err := checkedUint32ToInt(info.OriginalSize)
	if err != nil {
		return nil, fmt.Errorf("resolve output size for %s: %w", name, err)
	}

	data, _, err := lzss.DecompressFromReader(sr, outLen, nil)
	if err != nil {
		return nil, fmt.Errorf("decompress entry %s: %w", name, err)
	}

	return data, nil
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

// readerOnly hides optional interfaces (WriterTo) from an io.Reader.
// io.SectionReader implements WriterTo since Go 1.22;
// without this wrapper io.CopyBuffer ignores the caller-supplied buffer and allocates 32 KiB per call.
type readerOnly struct{ io.Reader }

// writerOnly hides optional interfaces (ReaderFrom) from an io.Writer.
// *os.File implements ReaderFrom on Windows;
// without this wrapper io.CopyBuffer ignores the caller-supplied buffer and allocates 32 KiB per call.
type writerOnly struct{ io.Writer }

// copyEntryPayloadTo copies one entry payload (decompressing if needed) directly into dst
// without spawning a goroutine or pipe. buf is used for uncompressed copies; nil is safe.
// Small compressed entries use bounded buffers; larger entries are decoded as a stream.
func (r *Reader) copyEntryPayloadTo(info *EntryInfo, dst io.Writer, buf []byte) (int64, error) {
	if dst == nil {
		return 0, ErrNilWriter
	}

	sr := io.NewSectionReader(r.ra, int64(info.Offset), int64(info.DataSize))
	if !info.IsCompressed() {
		return io.CopyBuffer(writerOnly{dst}, readerOnly{sr}, buf)
	}

	outLen, err := checkedUint32ToInt(info.OriginalSize)
	if err != nil {
		return 0, fmt.Errorf("resolve output size for %s: %w", info.Path, err)
	}

	if outLen <= maxBufferedCompressedCopySize && info.DataSize <= maxBufferedCompressedCopySize {
		// Avoid the stream decoder's fixed history buffer for tiny entries.
		packedSize, err := checkedUint32ToInt(info.DataSize)
		if err != nil {
			return 0, fmt.Errorf("resolve packed size for %s: %w", info.Path, err)
		}
		packed := make([]byte, packedSize)
		if _, err := io.ReadFull(sr, packed); err != nil {
			return 0, fmt.Errorf("read packed entry %s: %w", info.Path, err)
		}

		data, _, err := lzss.DecompressBlock(packed, outLen, nil)
		if err != nil {
			return 0, fmt.Errorf("decompress entry %s: %w", info.Path, err)
		}
		if err := writePayloadBytes(dst, data); err != nil {
			return 0, fmt.Errorf("write decompressed entry %s: %w", info.Path, err)
		}

		return int64(len(data)), nil
	}

	if _, err := lzss.DecompressToWriter(dst, sr, outLen, nil); err != nil {
		return 0, err
	}

	return int64(outLen), nil
}

// CopyEntryTo decompresses and copies the named entry into dst using the provided buf.
// Unlike OpenEntry, it does not spawn a goroutine or pipe, making it more efficient
// for callers that only need to push entry content into an io.Writer (os.File, http.ResponseWriter).
// buf may be nil; a default buffer is used for the uncompressed path.
func (r *Reader) CopyEntryTo(name string, dst io.Writer, buf []byte) (int64, error) {
	if r == nil || r.ra == nil {
		return 0, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	info := r.findEntryByName(name)
	if info == nil {
		return 0, fmt.Errorf("%w: %s", ErrEntryNotFound, name)
	}

	return r.copyEntryPayloadTo(info, dst, buf)
}

// CopyEntryInfoTo decompresses and copies entry described by info into dst using the provided buf.
// Unlike OpenEntryInfo, it does not spawn a goroutine or pipe.
// buf may be nil; a default buffer is used for the uncompressed path.
func (r *Reader) CopyEntryInfoTo(info EntryInfo, dst io.Writer, buf []byte) (int64, error) {
	if r == nil || r.ra == nil {
		return 0, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	return r.copyEntryPayloadTo(&info, dst, buf)
}

// OpenPackedEntryInfo opens a read stream over the raw stored bytes of an entry.
// The returned reader yields compressed bytes for LZSS-compressed entries no decompression is applied.
// Use this for selective replace in Editor, hash tooling,
// or any consumer that needs the packed payload verbatim.
func (r *Reader) OpenPackedEntryInfo(info EntryInfo) (io.ReadCloser, error) {
	if r == nil || r.ra == nil {
		return nil, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}

	sr := io.NewSectionReader(r.ra, int64(info.Offset), int64(info.DataSize))
	return nopCloser{Reader: sr}, nil
}

// CopyPackedEntryInfoTo copies the raw stored bytes of an entry into dst.
// Like OpenPackedEntryInfo, it yields compressed bytes for compressed entries.
func (r *Reader) CopyPackedEntryInfoTo(info EntryInfo, dst io.Writer) (int64, error) {
	if r == nil || r.ra == nil {
		return 0, ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}

	sr := io.NewSectionReader(r.ra, int64(info.Offset), int64(info.DataSize))
	return io.Copy(dst, sr)
}

// checkedUint32ToInt converts uint32 to int with platform-safe overflow check.
func checkedUint32ToInt(v uint32) (int, error) {
	if uint64(v) > uint64(math.MaxInt) {
		return 0, ErrSizeOverflow
	}

	return int(v), nil
}

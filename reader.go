// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
)

const (
	// readerScanChunkSize is a chunk size used by null-terminated string scanner.
	readerScanChunkSize = 256
	// readerEntryBufferSize is a sequential read buffer for entry table parsing.
	readerEntryBufferSize = 64 * 1024
)

var (
	// entryTableReaderPool reuses buffered readers for sequential table parsing.
	entryTableReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReaderSize(bytes.NewReader(nil), readerEntryBufferSize)
		},
	}
)

// Reader provides read-only access to a parsed PBO file.
type Reader struct {
	// ra is the underlying random-access reader used for payload reads.
	ra io.ReaderAt
	// file is set when Reader owns an *os.File opened via Open.
	file *os.File
	// header stores the fixed 21-byte PBO header block.
	header []byte
	// headers are kept in parse order for deterministic behavior.
	headers []headerPair
	// entries stores parsed immutable entry metadata.
	entries []EntryInfo
	// size is total source size in bytes.
	size int64
	// dataStart is absolute offset of first payload byte.
	dataStart int64
	// mu guards closed state and close operation.
	mu sync.Mutex
	// sha1Trailer stores optional trailer hash when present.
	sha1Trailer [shaSize]byte
	// hasTrailer reports whether trailing 0x00 + SHA1 was detected.
	hasTrailer bool
	// closed reports whether Close was already called.
	closed bool
}

// headerPair is internal parsed representation of header key-value pair.
type headerPair struct {
	// Key is a header key string.
	Key string
	// Value is header value paired with Key.
	Value string
}

// Open opens PBO file by path and parses index/header structures.
func Open(path string) (*Reader, error) {
	return OpenWithOptions(path, ReaderOptions{})
}

// OpenWithOptions opens PBO file by path and parses index/header structures using explicit reader options.
func OpenWithOptions(path string, opts ReaderOptions) (*Reader, error) {
	opts.applyDefaults()

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PBO: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat: %w", err)
	}

	r, err := NewReaderFromReaderAtWithOptions(f, fi.Size(), opts)
	if err != nil {
		_ = f.Close()
		return nil, err
	}

	r.file = f
	r.ra = f
	r.size = fi.Size()
	return r, nil
}

// NewReaderFromReaderAt parses PBO from existing ReaderAt and known size.
func NewReaderFromReaderAt(ra io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderFromReaderAtWithOptions(ra, size, ReaderOptions{})
}

// NewReaderFromReaderAtWithOptions parses PBO from existing ReaderAt and known size using explicit reader options.
func NewReaderFromReaderAtWithOptions(ra io.ReaderAt, size int64, opts ReaderOptions) (*Reader, error) {
	opts.applyDefaults()

	r := &Reader{ra: ra, size: size}
	if err := r.parse(ra, size, opts); err != nil {
		return nil, err
	}

	return r, nil
}

// Entries returns a copy of parsed entries.
func (r *Reader) Entries() []EntryInfo {
	if r == nil {
		return nil
	}

	entries := make([]EntryInfo, len(r.entries))
	copy(entries, r.entries)
	return entries
}

// Headers returns parsed headers in original order.
func (r *Reader) Headers() []HeaderPair {
	if r == nil {
		return nil
	}

	out := make([]HeaderPair, len(r.headers))
	for i := range r.headers {
		out[i].Key = r.headers[i].Key
		out[i].Value = r.headers[i].Value
	}

	return out
}

// Close closes the underlying file if reader owns one.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	r.closed = true
	if r.file != nil {
		return r.file.Close()
	}

	return nil
}

// SHA1Trailer returns parsed 20-byte trailer hash when present.
func (r *Reader) SHA1Trailer() ([20]byte, bool) {
	if r == nil || !r.hasTrailer {
		var z [20]byte
		return z, false
	}

	return r.sha1Trailer, true
}

// parse reads and validates PBO structure from ReaderAt.
func (r *Reader) parse(ra io.ReaderAt, size int64, opts ReaderOptions) error {
	header, headers, off, err := parseHeaderSection(ra)
	if err != nil {
		return err
	}
	r.header = header
	r.headers = headers

	// Parse entry table with sequential buffered reads to reduce ReadAt syscall overhead.
	entriesEnd, err := r.parseEntriesBuffered(ra, off, size)
	if err != nil {
		return err
	}

	r.dataStart = entriesEnd
	if err := resolveEntryOffsets(r.entries, entriesEnd, size, opts.OffsetMode); err != nil {
		return err
	}
	if opts.EnableJunkFilter {
		r.entries = filterJunkEntries(r.entries)
	}

	// check for SHA1 trailer
	if size >= 21 {
		var tail [21]byte
		if _, err := ra.ReadAt(tail[:], size-21); err == nil && tail[0] == 0x00 {
			r.hasTrailer = true
			copy(r.sha1Trailer[:], tail[1:21])
		}
	}

	return nil
}

// parseHeaderSection parses fixed header and key-value header pairs and returns entry table offset.
func parseHeaderSection(ra io.ReaderAt) ([]byte, []headerPair, int64, error) {
	header := make([]byte, headerSize)
	if _, err := ra.ReadAt(header, 0); err != nil {
		if err == io.EOF {
			return nil, nil, 0, fmt.Errorf("%w: short header", ErrInvalidHeader)
		}

		return nil, nil, 0, fmt.Errorf("read header: %w", err)
	}

	// The first directory entry must be "Vers".
	if MimeType(binary.LittleEndian.Uint32(header[1:5])) != MimeHeader {
		return nil, nil, 0, ErrInvalidHeader
	}

	headers := make([]headerPair, 0, 4)
	off := int64(headerSize)
	for {
		key, n, err := readNullTerminated(ra, off)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("read header key: %w", err)
		}

		off += int64(n)
		if key == "" {
			break
		}

		value, n, err := readNullTerminated(ra, off)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("read header value: %w", err)
		}

		off += int64(n)
		headers = append(headers, headerPair{Key: key, Value: value})
	}

	return header, headers, off, nil
}

// parseEntriesBuffered parses entry records from index table and returns payload start offset.
func (r *Reader) parseEntriesBuffered(ra io.ReaderAt, tableOffset int64, size int64) (int64, error) {
	if tableOffset >= size {
		return 0, fmt.Errorf("read entry filename: %w", io.EOF)
	}

	sr := io.NewSectionReader(ra, tableOffset, size-tableOffset)
	br := entryTableReaderPool.Get().(*bufio.Reader) //nolint:forcetypeassert // pool contains only *bufio.Reader
	br.Reset(sr)
	defer entryTableReaderPool.Put(br)

	off := tableOffset
	var spill []byte
	if r.entries == nil {
		estimatedCap := estimateEntryCapacity(size - tableOffset)
		r.entries = make([]EntryInfo, 0, estimatedCap)
	}

	for {
		filename, nameBytes, err := readNullTerminatedBuffered(br, &spill)
		if err != nil {
			return 0, fmt.Errorf("read entry filename: %w", err)
		}

		off += int64(nameBytes)
		var fields [20]byte
		if _, err := io.ReadFull(br, fields[:]); err != nil {
			return 0, fmt.Errorf("read entry fields: %w", err)
		}

		off += int64(len(fields))
		mimeType := MimeType(binary.LittleEndian.Uint32(fields[0:4]))
		originalSize := binary.LittleEndian.Uint32(fields[4:8])
		offset := binary.LittleEndian.Uint32(fields[8:12])
		timestamp := binary.LittleEndian.Uint32(fields[12:16])
		dataSize := binary.LittleEndian.Uint32(fields[16:20])

		if filename == "" && mimeType == 0 && originalSize == 0 && offset == 0 && timestamp == 0 && dataSize == 0 {
			return off, nil
		}

		if len(filename) > maxNameLen {
			return 0, ErrFileNameTooLong
		}

		r.entries = append(r.entries, EntryInfo{
			Path:         filename,
			Offset:       offset,
			DataSize:     dataSize,
			OriginalSize: originalSize,
			TimeStamp:    timestamp,
			MimeType:     mimeType,
		})
	}
}

// estimateEntryCapacity returns a conservative initial capacity for parsed entry metadata.
func estimateEntryCapacity(remainingBytes int64) int {
	if remainingBytes <= 0 {
		return 0
	}

	const (
		minCap = 128
		maxCap = 8192
		// remainingBytes includes payload region, so keep estimate intentionally conservative.
		avgEntryBytes = 512
	)

	estimated := int(remainingBytes / avgEntryBytes)
	if estimated < minCap {
		return minCap
	}
	if estimated > maxCap {
		return maxCap
	}

	return estimated
}

// resolveEntryOffsets applies selected offset policy and validates payload bounds.
func resolveEntryOffsets(entries []EntryInfo, dataStart int64, totalSize int64, mode OffsetMode) error {
	switch mode {
	case OffsetModeSequential:
		if err := assignSequentialOffsets(entries, dataStart); err != nil {
			return err
		}
	case OffsetModeStoredCompat:
		usedStored, err := tryAssignStoredOffsets(entries, dataStart, totalSize)
		if err != nil {
			if err := assignSequentialOffsets(entries, dataStart); err != nil {
				return err
			}
		}
		if !usedStored {
			if err := assignSequentialOffsets(entries, dataStart); err != nil {
				return err
			}
		}
	case OffsetModeStoredStrict:
		usedStored, err := tryAssignStoredOffsets(entries, dataStart, totalSize)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidEntryOffset, err)
		}
		if !usedStored {
			if err := assignSequentialOffsets(entries, dataStart); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%w: unknown offset mode %q", ErrInvalidEntryOffset, mode)
	}

	if err := validateResolvedOffsets(entries, dataStart, totalSize); err != nil {
		return err
	}

	return nil
}

// assignSequentialOffsets derives payload offsets from dataStart and previous entry sizes.
func assignSequentialOffsets(entries []EntryInfo, dataStart int64) error {
	if dataStart < 0 || uint64(dataStart) > uint64(math.MaxUint32) {
		return fmt.Errorf("%w: data start offset %d", ErrSizeOverflow, dataStart)
	}

	current := uint32(dataStart) //nolint:gosec // bounded by maxPBOData check above
	for i := range entries {
		entries[i].Offset = current

		if uint64(entries[i].DataSize) > uint64(math.MaxUint32-current) {
			return fmt.Errorf("%w: entry %s size would exceed 4 GiB", ErrSizeOverflow, entries[i].Path)
		}

		current += entries[i].DataSize
	}

	return nil
}

// tryAssignStoredOffsets tries to apply stored non-zero index offsets in relative or absolute form.
func tryAssignStoredOffsets(entries []EntryInfo, dataStart int64, totalSize int64) (bool, error) {
	if len(entries) == 0 {
		return false, nil
	}

	hasMeaningful := false
	for i := range entries {
		if entries[i].Offset != 0 {
			hasMeaningful = true
			break
		}
	}
	if !hasMeaningful {
		return false, nil
	}

	first := entries[0].Offset
	// Heuristic: first offset zero usually means relative, first >= dataStart usually absolute.
	tryRelativeFirst := first == 0 || int64(first) < dataStart
	if tryRelativeFirst {
		if err := assignStoredOffsets(entries, dataStart, totalSize, false); err == nil {
			return true, nil
		}
		if err := assignStoredOffsets(entries, dataStart, totalSize, true); err == nil {
			return true, nil
		}
	} else {
		if err := assignStoredOffsets(entries, dataStart, totalSize, true); err == nil {
			return true, nil
		}
		if err := assignStoredOffsets(entries, dataStart, totalSize, false); err == nil {
			return true, nil
		}
	}

	return false, errors.New("stored offsets are malformed")
}

// assignStoredOffsets applies stored offsets as absolute or relative-to-dataStart values.
func assignStoredOffsets(entries []EntryInfo, dataStart int64, totalSize int64, absolute bool) error {
	prev := int64(-1)
	adjust := dataStart
	if absolute {
		adjust = 0
	}

	for i := range entries {
		raw := int64(entries[i].Offset)
		resolved := raw + adjust
		if resolved < dataStart {
			return fmt.Errorf("entry %s offset before data start", entries[i].Path)
		}
		if resolved < 0 || uint64(resolved) > uint64(math.MaxUint32) {
			return fmt.Errorf("entry %s offset out of range", entries[i].Path)
		}
		if resolved < prev {
			return fmt.Errorf("entry %s offset is not monotonic", entries[i].Path)
		}

		end := resolved + int64(entries[i].DataSize)
		if end < resolved || end > totalSize {
			return fmt.Errorf("entry %s payload out of file bounds", entries[i].Path)
		}

		entries[i].Offset = uint32(resolved) //nolint:gosec // bounded by range check above
		prev = resolved
	}

	return nil
}

// validateResolvedOffsets validates final offsets regardless of policy branch.
func validateResolvedOffsets(entries []EntryInfo, dataStart int64, totalSize int64) error {
	for i := range entries {
		offset := int64(entries[i].Offset)
		if offset < dataStart {
			return fmt.Errorf("%w: entry %s offset before data start", ErrInvalidEntryOffset, entries[i].Path)
		}

		end := offset + int64(entries[i].DataSize)
		if end < offset || end > totalSize {
			return fmt.Errorf("%w: entry %s payload out of file bounds", ErrInvalidEntryOffset, entries[i].Path)
		}
	}

	return nil
}

// filterJunkEntries removes malformed or unusable entries from parsed table.
func filterJunkEntries(entries []EntryInfo) []EntryInfo {
	if len(entries) == 0 {
		return entries
	}

	filtered := make([]EntryInfo, 0, len(entries))
	for i := range entries {
		e := entries[i]
		if e.DataSize == 0 {
			continue
		}
		if e.MimeType == MimeCompress && e.OriginalSize == 0 {
			continue
		}
		if _, err := normalizeExtractEntryPath(e.Path); err != nil {
			continue
		}

		filtered = append(filtered, e)
	}

	return filtered
}

// readNullTerminatedBuffered reads a NUL-terminated string from buffered stream.
func readNullTerminatedBuffered(br *bufio.Reader, spill *[]byte) (string, int, error) {
	consumed := 0
	*spill = (*spill)[:0]

	for {
		chunk, err := br.ReadSlice(0)
		consumed += len(chunk)

		if err == bufio.ErrBufferFull {
			*spill = append(*spill, chunk...)
			continue
		}

		if err != nil {
			return "", 0, err
		}

		segment := chunk[:len(chunk)-1]
		if len(*spill) == 0 {
			return string(segment), consumed, nil
		}

		*spill = append(*spill, segment...)
		return string(*spill), consumed, nil
	}
}

// readNullTerminated reads a zero-terminated string from ReaderAt starting at offset.
func readNullTerminated(ra io.ReaderAt, offset int64) (string, int, error) {
	total := 0
	var out []byte

	// Scan larger chunks to avoid one-byte ReadAt calls on large indices.
	var chunk [readerScanChunkSize]byte
	for {
		n, err := ra.ReadAt(chunk[:], offset+int64(total))
		if n > 0 {
			part := chunk[:n]
			if idx := bytes.IndexByte(part, 0); idx >= 0 {
				consumed := total + idx + 1
				if len(out) == 0 {
					return string(part[:idx]), consumed, nil
				}

				out = append(out, part[:idx]...)
				return string(out), consumed, nil
			}

			if len(out) == 0 {
				// Most names fit in one chunk; lazy allocation keeps short names cheap.
				out = make([]byte, 0, n*2)
			}

			out = append(out, part...)
			total += n
		}

		if err != nil {
			return "", 0, err
		}

		if n == 0 {
			return "", 0, io.EOF
		}
	}
}

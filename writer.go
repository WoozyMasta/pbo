// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// defaultPackWriterPool reuses default-sized bufio writers between Pack calls.
	defaultPackWriterPool = sync.Pool{
		New: func() any {
			return bufio.NewWriterSize(io.Discard, DefaultWriteBuffer)
		},
	}
	// defaultPackCopyBufferPool reuses payload copy buffers between Pack calls.
	defaultPackCopyBufferPool = sync.Pool{
		New: func() any {
			return new([packCopyBufferSize]byte)
		},
	}
)

const (
	// packCopyBufferSize is per-pack temporary buffer used by streaming payload copy.
	packCopyBufferSize = 64 * 1024
)

// writtenEntry stores concrete entry values produced during payload write.
type writtenEntry struct {
	path                 string
	dataSize             uint32
	originalSize         uint32
	mime                 MimeType
	timestamp            uint32
	compressionCandidate bool
}

// rewriteEntry describes one payload source for archive rewrite core.
type rewriteEntry struct {
	input  *Input
	source *EntryInfo
	path   string
}

// rewriteArchiveResult contains rewrite core result and written metadata.
type rewriteArchiveResult struct {
	packResult *PackResult
	entries    []EntryInfo
	headers    []HeaderPair
}

// Pack writes a PBO to out from the given inputs.
// Inputs are sorted by path for deterministic output.
func Pack(ctx context.Context, out io.WriteSeeker, inputs []Input, opts PackOptions) (*PackResult, error) {
	if len(inputs) == 0 {
		return nil, ErrEmptyInputs
	}

	opts.applyDefaults()

	rewritePlan, err := preparePackRewritePlan(inputs)
	if err != nil {
		return nil, err
	}

	return rewriteArchive(ctx, out, nil, rewritePlan, opts)
}

// PackFile writes a PBO to outPath and appends a SHA1 trailer.
func PackFile(ctx context.Context, outPath string, inputs []Input, opts PackOptions) (*PackResult, error) {
	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create PBO file: %w", err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	res, err := Pack(ctx, f, inputs, opts)
	if err != nil {
		return nil, err
	}

	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync PBO file: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close PBO file: %w", err)
	}
	f = nil

	if err := writeSHA1Trailer(outPath); err != nil {
		return nil, fmt.Errorf("write SHA1 trailer: %w", err)
	}

	return res, nil
}

// PackAndHash writes a PBO to out and calculates hash set over written bytes.
// The output writer must also implement io.ReaderAt for hash calculation.
func PackAndHash(
	ctx context.Context,
	out io.WriteSeeker,
	inputs []Input,
	opts PackOptions,
	signVersion SignVersion,
	gameType GameType,
) (*PackResult, HashSet, error) {
	var hs HashSet

	if out == nil {
		return nil, hs, ErrNilWriter
	}

	ra, ok := out.(io.ReaderAt)
	if !ok {
		return nil, hs, ErrReaderAtRequired
	}

	if err := validateSignHashArgs(signVersion, gameType); err != nil {
		return nil, hs, err
	}

	if len(inputs) == 0 {
		return nil, hs, ErrEmptyInputs
	}

	opts.applyDefaults()
	rewritePlan, err := preparePackRewritePlan(inputs)
	if err != nil {
		return nil, hs, err
	}

	details, err := rewriteArchiveDetailed(ctx, out, nil, rewritePlan, opts)
	if err != nil {
		return nil, hs, err
	}

	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, hs, fmt.Errorf("seek end for hash: %w", err)
	}

	hs, err = computeHashSetFromPackedParts(
		ra,
		size,
		false,
		details.headers,
		details.entries,
		signVersion,
		gameType,
	)
	if err != nil {
		return nil, hs, err
	}

	return details.packResult, hs, nil
}

// PackAndHashFile writes a PBO to outPath, returns hash set, and appends SHA1 trailer.
func PackAndHashFile(
	ctx context.Context,
	outPath string,
	inputs []Input,
	opts PackOptions,
	signVersion SignVersion,
	gameType GameType,
) (*PackResult, HashSet, error) {
	var hs HashSet

	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, hs, fmt.Errorf("create PBO file: %w", err)
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	res, hs, err := PackAndHash(ctx, f, inputs, opts, signVersion, gameType)
	if err != nil {
		return nil, hs, err
	}

	if err := f.Sync(); err != nil {
		return nil, hs, fmt.Errorf("sync PBO file: %w", err)
	}

	if err := f.Close(); err != nil {
		return nil, hs, fmt.Errorf("close PBO file: %w", err)
	}
	f = nil

	if err := writeSHA1Trailer(outPath); err != nil {
		return nil, hs, fmt.Errorf("write SHA1 trailer: %w", err)
	}

	return res, hs, nil
}

// acquirePackWriter returns a buffered writer and release callback for Pack.
func acquirePackWriter(out io.Writer, size int) (*bufio.Writer, func()) {
	if size == DefaultWriteBuffer {
		w := defaultPackWriterPool.Get().(*bufio.Writer) //nolint:forcetypeassert // pool contains only *bufio.Writer
		w.Reset(out)

		return w, func() {
			w.Reset(io.Discard)
			defaultPackWriterPool.Put(w)
		}
	}

	return bufio.NewWriterSize(out, size), func() {}
}

// acquirePackCopyBuffer returns reusable payload copy buffer and release callback.
func acquirePackCopyBuffer() ([]byte, func()) {
	arr := defaultPackCopyBufferPool.Get().(*[packCopyBufferSize]byte) //nolint:forcetypeassert // pool contains only fixed-size buffers
	buf := arr[:]

	return buf, func() {
		defaultPackCopyBufferPool.Put(arr)
	}
}

// preparePackRewritePlan normalizes and sorts pack inputs for deterministic rewrite pass.
func preparePackRewritePlan(inputs []Input) ([]rewriteEntry, error) {
	sorted := make([]Input, len(inputs))
	copy(sorted, inputs)

	for i := range sorted {
		normalizedPath, err := normalizeArchiveEntryPath(sorted[i].Path)
		if err != nil {
			return nil, err
		}

		sorted[i].Path = normalizedPath
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	if err := validateUniqueEntryPaths(sorted); err != nil {
		return nil, err
	}

	var total int64
	for i := range sorted {
		if sorted[i].SizeHint > 0 {
			total += sorted[i].SizeHint
		}
	}

	if total > maxPBOData {
		return nil, fmt.Errorf("%w: estimated data %d exceeds 4 GiB", ErrSizeOverflow, total)
	}

	rewritePlan := make([]rewriteEntry, len(sorted))
	for i := range sorted {
		rewritePlan[i] = rewriteEntry{
			path:  sorted[i].Path,
			input: &sorted[i],
		}
	}

	return rewritePlan, nil
}

// openInputReader opens source stream for one input.
func openInputReader(in Input) (io.ReadCloser, error) {
	if in.Open == nil {
		return nil, fmt.Errorf("input %s: Open is nil", in.Path)
	}

	rc, err := in.Open()
	if err != nil {
		return nil, fmt.Errorf("open input %s: %w", in.Path, err)
	}

	return rc, nil
}

// writeInputPayload writes one entry payload according to precomputed compression plan.
func writeInputPayload(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	useCompression bool,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	if !useCompression {
		return writeUncompressedPayload(dst, src, in, currentOffset, copyBuf)
	}

	return writeCompressedCandidatePayload(dst, src, in, opts, currentOffset, copyBuf)
}

// rewriteArchive is shared writer core for Pack and editor commit flows.
func rewriteArchive(
	ctx context.Context,
	out io.WriteSeeker,
	src io.ReaderAt,
	rewritePlan []rewriteEntry,
	opts PackOptions,
) (*PackResult, error) {
	details, err := rewriteArchiveDetailed(ctx, out, src, rewritePlan, opts)
	if err != nil {
		return nil, err
	}

	return details.packResult, nil
}

// rewriteArchiveDetailed runs shared rewrite core and returns written metadata.
func rewriteArchiveDetailed(
	ctx context.Context,
	out io.WriteSeeker,
	src io.ReaderAt,
	rewritePlan []rewriteEntry,
	opts PackOptions,
) (*rewriteArchiveResult, error) {
	startedAt := time.Now()

	if out == nil {
		return nil, ErrNilWriter
	}

	if ctx == nil {
		ctx = context.Background()
	}

	opts.applyDefaults()

	compressMatcher, err := newCompressMatcher(opts.Compress, opts.CompressMatcherOptions)
	if err != nil {
		return nil, fmt.Errorf("compile compress rules: %w", err)
	}

	w, releaseWriter := acquirePackWriter(out, opts.WriterBufferSize)
	defer releaseWriter()

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
	if _, err := w.Write(header); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	writtenHeaders := make([]HeaderPair, 0, len(opts.Headers))
	for _, h := range opts.Headers {
		key := h.Key
		value := h.Value
		if strings.EqualFold(strings.TrimSpace(key), "prefix") {
			value = NormalizePrefixHeader(value)
		}

		writtenHeaders = append(writtenHeaders, HeaderPair{Key: key, Value: value})

		if _, err := w.WriteString(key); err != nil {
			return nil, fmt.Errorf("write header key: %w", err)
		}

		if err := w.WriteByte(0); err != nil {
			return nil, fmt.Errorf("write header key terminator: %w", err)
		}

		if _, err := w.WriteString(value); err != nil {
			return nil, fmt.Errorf("write header value: %w", err)
		}

		if err := w.WriteByte(0); err != nil {
			return nil, fmt.Errorf("write header value terminator: %w", err)
		}
	}

	if err := w.WriteByte(0); err != nil {
		return nil, fmt.Errorf("write header terminator: %w", err)
	}

	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flush headers: %w", err)
	}

	entriesStart, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("seek after headers: %w", err)
	}

	var placeholder [20]byte
	for _, item := range rewritePlan {
		if _, err := w.WriteString(item.path); err != nil {
			return nil, fmt.Errorf("write entry path: %w", err)
		}

		if err := w.WriteByte(0); err != nil {
			return nil, fmt.Errorf("write entry path terminator: %w", err)
		}

		if _, err := w.Write(placeholder[:]); err != nil {
			return nil, fmt.Errorf("write entry placeholder: %w", err)
		}
	}

	if err := w.WriteByte(0); err != nil {
		return nil, fmt.Errorf("write entries terminator: %w", err)
	}

	if _, err := w.Write(placeholder[:]); err != nil {
		return nil, fmt.Errorf("write entries tail fields: %w", err)
	}

	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flush after entries: %w", err)
	}

	dataStart, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	if dataStart > maxPBOData {
		return nil, fmt.Errorf("%w: data start offset %d", ErrSizeOverflow, dataStart)
	}

	written := make([]writtenEntry, 0, len(rewritePlan))
	entries := make([]EntryInfo, 0, len(rewritePlan))
	currentOffset := uint32(dataStart) //nolint:gosec // checked above against maxPBOData
	var (
		rawBytes                  int64
		compressedBytes           int64
		compressedEntries         int
		skippedCompressionEntries int
	)

	copyBuf, releaseCopyBuffer := acquirePackCopyBuffer()
	defer releaseCopyBuffer()

	appendWrittenEntry := func(path string, record writtenEntry) {
		entryInfo := EntryInfo{
			Path:         path,
			Offset:       currentOffset,
			DataSize:     record.dataSize,
			OriginalSize: record.originalSize,
			TimeStamp:    record.timestamp,
			MimeType:     record.mime,
		}

		written = append(written, record)
		entries = append(entries, entryInfo)

		if record.mime == MimeCompress {
			compressedEntries++
			compressedBytes += int64(record.dataSize)
		} else {
			rawBytes += int64(record.dataSize)
		}

		if record.compressionCandidate && record.mime != MimeCompress {
			skippedCompressionEntries++
		}

		if opts.OnEntryDone != nil {
			opts.OnEntryDone(PackEntryProgress{
				Path:                 path,
				Offset:               currentOffset,
				DataSize:             record.dataSize,
				OriginalSize:         record.originalSize,
				MimeType:             record.mime,
				CompressionCandidate: record.compressionCandidate,
				Compressed:           record.mime == MimeCompress,
			})
		}

		currentOffset += record.dataSize
	}

	for _, item := range rewritePlan {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if item.source != nil {
			if src == nil {
				return nil, ErrNilReader
			}

			record, err := writeSourcePackedPayload(w, src, item.path, *item.source, currentOffset, copyBuf)
			if err != nil {
				return nil, err
			}

			appendWrittenEntry(item.path, record)

			continue
		}

		record, err := writeRewriteInputPayload(
			w,
			item,
			opts,
			compressMatcher,
			currentOffset,
			copyBuf,
		)
		if err != nil {
			return nil, err
		}

		appendWrittenEntry(item.path, record)
	}

	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flush payloads: %w", err)
	}

	pos := entriesStart
	var entryFields [20]byte
	for i, item := range rewritePlan {
		pos += int64(len(item.path) + 1)
		if _, err := out.Seek(pos, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek to entry %d: %w", i, err)
		}

		record := written[i]
		binary.LittleEndian.PutUint32(entryFields[0:4], uint32(record.mime))
		binary.LittleEndian.PutUint32(entryFields[4:8], record.originalSize)
		// Common tooling emits zero in index offset and derives offsets sequentially.
		binary.LittleEndian.PutUint32(entryFields[8:12], 0)
		binary.LittleEndian.PutUint32(entryFields[12:16], record.timestamp)
		binary.LittleEndian.PutUint32(entryFields[16:20], record.dataSize)
		if _, err := out.Write(entryFields[:]); err != nil {
			return nil, fmt.Errorf("patch entry %d: %w", i, err)
		}

		pos += 20
	}

	return &rewriteArchiveResult{
		packResult: &PackResult{
			WrittenEntries:            len(written),
			DataSize:                  int64(currentOffset) - dataStart,
			IndexSize:                 dataStart - entriesStart,
			RawBytes:                  rawBytes,
			CompressedBytes:           compressedBytes,
			CompressedEntries:         compressedEntries,
			SkippedCompressionEntries: skippedCompressionEntries,
			Duration:                  time.Since(startedAt),
		},
		entries: entries,
		headers: writtenHeaders,
	}, nil
}

// writeRewriteInputPayload opens and writes one input-backed rewrite item.
func writeRewriteInputPayload(
	dst io.Writer,
	item rewriteEntry,
	opts PackOptions,
	matcher *compressMatcher,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	if item.input == nil {
		return writtenEntry{}, fmt.Errorf("entry %s: missing input/source", item.path)
	}

	useCompression := shouldUseCompressionForInput(opts, matcher, *item.input)

	rc, err := openInputReader(*item.input)
	if err != nil {
		return writtenEntry{}, err
	}

	record, writeErr := writeInputPayload(
		dst,
		rc,
		*item.input,
		opts,
		useCompression,
		currentOffset,
		copyBuf,
	)
	closeErr := rc.Close()
	if writeErr != nil {
		return writtenEntry{}, writeErr
	}
	if closeErr != nil {
		return writtenEntry{}, fmt.Errorf("close input %s: %w", item.input.Path, closeErr)
	}

	record.compressionCandidate = useCompression

	return record, nil
}

// shouldUseCompressionForInput reports whether input should enter compression candidate path.
func shouldUseCompressionForInput(opts PackOptions, matcher *compressMatcher, in Input) bool {
	if matcher == nil {
		return false
	}

	if shouldSkipCompressBySizeHint(opts, in.SizeHint) {
		return false
	}

	if in.SizeHint > int64(^uint32(0)) {
		return false
	}

	if in.SizeHint > 0 {
		return shouldCompress(opts, matcher, in.Path, uint32(in.SizeHint))
	}

	return matcher.Match(in.Path)
}

// shouldSkipCompressBySizeHint reports whether known size hint guarantees no compression attempt.
func shouldSkipCompressBySizeHint(opts PackOptions, sizeHint int64) bool {
	if sizeHint <= 0 {
		return false
	}

	return sizeHint < int64(opts.MinCompressSize) || sizeHint > int64(opts.MaxCompressSize)
}

// writeCompressedCandidatePayload handles compression candidate with in-memory path for known-size inputs.
// Unknown-size and out-of-range candidates are streamed raw.
func writeCompressedCandidatePayload(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	maxEntrySize := int64(^uint32(0)) - int64(currentOffset)
	if !shouldUseInMemoryCompressPath(opts, in.SizeHint, maxEntrySize) {
		return writeUncompressedPayload(dst, src, in, currentOffset, copyBuf)
	}

	return writeCompressedCandidatePayloadInMemory(dst, src, in, opts, currentOffset, copyBuf, maxEntrySize)
}

// writeUncompressedPayload streams payload directly into destination and records MimeNil metadata.
func writeUncompressedPayload(
	dst io.Writer,
	src io.Reader,
	in Input,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	maxEntrySize := int64(^uint32(0)) - int64(currentOffset)
	streamed, err := copyPayloadBounded(dst, src, maxEntrySize, copyBuf)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("stream input %s: %w", in.Path, err)
	}

	dataSize, err := checkedDataSize(in.Path, streamed, currentOffset)
	if err != nil {
		return writtenEntry{}, err
	}

	return writtenEntry{
		path:      in.Path,
		dataSize:  dataSize,
		mime:      MimeNil,
		timestamp: timeToUint32(in.ModTime),
	}, nil
}

// shouldUseInMemoryCompressPath reports whether compression candidate can use fast in-memory path.
func shouldUseInMemoryCompressPath(opts PackOptions, sizeHint int64, maxEntrySize int64) bool {
	if sizeHint <= 0 {
		return false
	}
	if sizeHint > maxEntrySize {
		return false
	}
	if sizeHint > int64(opts.MaxCompressSize) {
		return false
	}

	return true
}

// writeCompressedCandidatePayloadInMemory handles small/known-size candidates using in-memory compression.
func writeCompressedCandidatePayloadInMemory(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	currentOffset uint32,
	copyBuf []byte,
	maxEntrySize int64,
) (writtenEntry, error) {
	raw, err := readPayloadBounded(src, maxEntrySize, in.SizeHint, int64(opts.MaxCompressSize), copyBuf)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("stream input %s: %w", in.Path, err)
	}

	originalSize, err := checkedDataSize(in.Path, int64(len(raw)), currentOffset)
	if err != nil {
		return writtenEntry{}, err
	}

	record := writtenEntry{
		path:      in.Path,
		dataSize:  originalSize,
		mime:      MimeNil,
		timestamp: timeToUint32(in.ModTime),
	}
	if !shouldCompressBySize(opts, originalSize) {
		if _, err := dst.Write(raw); err != nil {
			return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
		}

		return record, nil
	}

	compressed, err := compressLZSS(raw)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("compress %s: %w", in.Path, err)
	}
	if len(compressed) >= len(raw) {
		if _, err := dst.Write(raw); err != nil {
			return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
		}

		return record, nil
	}

	dataSize, err := checkedDataSize(in.Path, int64(len(compressed)), currentOffset)
	if err != nil {
		return writtenEntry{}, err
	}

	record.dataSize = dataSize
	record.originalSize = originalSize
	record.mime = MimeCompress
	if _, err := dst.Write(compressed); err != nil {
		return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
	}

	return record, nil
}

// readPayloadBounded reads whole payload into memory with strict max-size enforcement.
func readPayloadBounded(src io.Reader, limit int64, sizeHint int64, inMemoryLimit int64, copyBuf []byte) ([]byte, error) {
	var dst bytes.Buffer
	if sizeHint > 0 && sizeHint <= inMemoryLimit {
		dst.Grow(int(sizeHint))
	}

	written, err := copyPayloadBounded(&dst, src, limit, copyBuf)
	if err != nil {
		return nil, err
	}
	if int64(dst.Len()) != written {
		return nil, fmt.Errorf("short read into memory (%d/%d)", dst.Len(), written)
	}

	return dst.Bytes(), nil
}

// writeSourcePackedPayload copies already packed bytes from source archive.
func writeSourcePackedPayload(
	dst io.Writer,
	src io.ReaderAt,
	path string,
	entry EntryInfo,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	size := int64(entry.DataSize)
	dataSize, err := checkedDataSize(path, size, currentOffset)
	if err != nil {
		return writtenEntry{}, err
	}

	sr := io.NewSectionReader(src, int64(entry.Offset), size)
	written, err := copyPayloadBounded(dst, sr, size, copyBuf)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("copy packed entry %s: %w", path, err)
	}
	if written != size {
		return writtenEntry{}, fmt.Errorf("copy packed entry %s: short read (%d/%d)", path, written, size)
	}

	return writtenEntry{
		path:         path,
		dataSize:     dataSize,
		originalSize: entry.OriginalSize,
		mime:         entry.MimeType,
		timestamp:    entry.TimeStamp,
	}, nil
}

// copyPayloadBounded streams payload from src to dst and enforces strict size limit.
func copyPayloadBounded(dst io.Writer, src io.Reader, limit int64, buf []byte) (int64, error) {
	if dst == nil {
		return 0, ErrNilWriter
	}
	if src == nil {
		return 0, ErrNilReader
	}
	if limit < 0 {
		return 0, ErrSizeOverflow
	}
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}

	var written int64
	emptyReads := 0
	for written < limit {
		chunkSize := len(buf)
		remaining := limit - written
		if int64(chunkSize) > remaining {
			chunkSize = int(remaining)
		}

		n, readErr := src.Read(buf[:chunkSize])
		if n > 0 {
			emptyReads = 0
			nw, writeErr := dst.Write(buf[:n])
			written += int64(nw)

			if writeErr != nil {
				return written, writeErr
			}
			if nw != n {
				return written, io.ErrShortWrite
			}
		}
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads > 100 {
				return written, io.ErrNoProgress
			}

			continue
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}

			return written, readErr
		}
	}

	// If we consumed exactly the limit, probe one extra byte to ensure source is not longer.
	if written == limit {
		var probe [1]byte
		n, err := src.Read(probe[:])
		if n > 0 {
			return written, ErrSizeOverflow
		}
		if err != nil && err != io.EOF {
			return written, err
		}
	}

	return written, nil
}

// checkedDataSize validates entry size for uint32-based PBO fields and running offset.
func checkedDataSize(path string, size int64, currentOffset uint32) (uint32, error) {
	if size < 0 || size > int64(^uint32(0)) {
		return 0, fmt.Errorf("%w: entry %s size %d is out of uint32 range", ErrSizeOverflow, path, size)
	}

	maxEntrySize := int64(^uint32(0)) - int64(currentOffset)
	if size > maxEntrySize {
		return 0, fmt.Errorf("%w: entry %s size would exceed 4 GiB", ErrSizeOverflow, path)
	}

	return uint32(size), nil
}

// validateUniqueEntryPaths ensures there are no duplicate logical entry paths.
func validateUniqueEntryPaths(inputs []Input) error {
	seen := make(map[string]string, len(inputs))
	for _, in := range inputs {
		key := strings.ToLower(in.Path)
		if existing, ok := seen[key]; ok {
			return fmt.Errorf("%w: %q conflicts with %q", ErrDuplicateEntryPath, in.Path, existing)
		}

		seen[key] = in.Path
	}

	return nil
}

// timeToUint32 converts time to uint32 Unix timestamp with bounds clamping.
func timeToUint32(t time.Time) uint32 {
	u := t.Unix()
	if u < 0 {
		return 0
	}

	if u > 0xffffffff {
		return 0xffffffff
	}

	return uint32(u)
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // Signature format requires SHA1.
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// compressionCandidateChunkSize bounds each retained piece of a compression candidate.
	compressionCandidateChunkSize = 1 * 1024 * 1024
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
	packResult    *PackResult
	entries       []EntryInfo
	headers       []HeaderPair
	headerSection []byte // encoded header+KV pairs; used to avoid re-reading for hash1
	indexBuf      []byte // final index block; used to avoid re-reading for hash1
	fileHash      []byte // inline file hash over sign-eligible packed bytes; nil when not requested
	dataStart     int64  // payload start offset in the written file
}

// computeHash1ForFile returns hash1 over PBO content.
// When sealing is active the on-disk bytes differ from what was written,
// so the full file is re-read.
// Otherwise the fixed sections are taken from memory
// and only the payload region is read from ra, avoiding re-reading header and index.
func computeHash1ForFile(
	details *rewriteArchiveResult,
	ra io.ReaderAt, fileEnd int64,
	sealedKey *SealedKey,
) ([]byte, error) {
	if parseSealedKey(sealedKey).enabled {
		return computeSignHash1(ra, fileEnd, false)
	}

	return computeHash1FromSections(details.headerSection, details.indexBuf, ra, details.dataStart, fileEnd)
}

// encodeHeaderSection re-encodes the header and KV pair bytes from memory.
// This avoids re-reading the file to hash the header section when computing hash1.
func encodeHeaderSection(header []byte, headers []HeaderPair) []byte {
	n := len(header) + 1
	for _, h := range headers {
		n += len(h.Key) + 1 + len(h.Value) + 1
	}
	buf := make([]byte, 0, n)
	buf = append(buf, header...)
	for _, h := range headers {
		buf = append(buf, h.Key...)
		buf = append(buf, 0)
		buf = append(buf, h.Value...)
		buf = append(buf, 0)
	}
	return append(buf, 0)
}

// Pack writes a PBO to out from the given inputs.
// Inputs are sorted by path for deterministic output. The archive starts at offset zero;
// truncatable outputs are reset before writing, and other outputs must be empty at offset zero.
// On success, the output position is at the end of the archive.
func Pack(ctx context.Context, out io.WriteSeeker, inputs []Input, opts PackOptions) (*PackResult, error) {
	rewritePlan, opts, err := preparePackRequest(inputs, opts)
	if err != nil {
		return nil, err
	}
	if err := preparePackOutput(out); err != nil {
		return nil, err
	}

	result, err := rewriteArchive(ctx, out, nil, rewritePlan, opts)
	if err != nil {
		return nil, err
	}
	if _, err := out.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("seek end after pack: %w", err)
	}

	return result, nil
}

// PackFile writes a PBO to outPath and appends a SHA1 trailer.
func PackFile(ctx context.Context, outPath string, inputs []Input, opts PackOptions) (*PackResult, error) {
	rewritePlan, opts, err := preparePackRequest(inputs, opts)
	if err != nil {
		return nil, err
	}

	var result *PackResult
	err = writePackFileAtomically(outPath, func(f *os.File) error {
		details, err := rewriteArchiveDetailed(ctx, f, nil, rewritePlan, opts)
		if err != nil {
			return err
		}

		fileEnd, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("seek end for trailer: %w", err)
		}

		hash1, err := computeHash1ForFile(details, f, fileEnd, opts.SealedKey)
		if err != nil {
			return fmt.Errorf("compute SHA1 trailer: %w", err)
		}

		var trailer [21]byte
		copy(trailer[1:], hash1)
		if _, err := f.WriteAt(trailer[:], fileEnd); err != nil {
			return fmt.Errorf("write SHA1 trailer: %w", err)
		}
		result = details.packResult

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
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

	opts.signHashVersion = signVersion
	opts.signHashGameType = gameType
	rewritePlan, opts, err := preparePackRequest(inputs, opts)
	if err != nil {
		return nil, hs, err
	}
	if err := preparePackOutput(out); err != nil {
		return nil, hs, err
	}

	details, err := rewriteArchiveDetailed(ctx, out, nil, rewritePlan, opts)
	if err != nil {
		return nil, hs, err
	}

	fileEnd, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, hs, fmt.Errorf("seek end for hash: %w", err)
	}

	hash1, err := computeHash1ForFile(details, ra, fileEnd, opts.SealedKey)
	if err != nil {
		return nil, hs, fmt.Errorf("hash1: %w", err)
	}

	nameHash := computeSignNameHash(details.entries)

	// Use inline file hash from pack when available; fall back to re-read for sealed PBOs.
	fileHash := details.fileHash
	if fileHash == nil {
		fileHash, err = computeSignFileHashFromReaderAt(ra, details.entries, signVersion, gameType)
		if err != nil {
			return nil, hs, fmt.Errorf("file hash: %w", err)
		}
	}

	prefix := pboPrefixFromHeaders(details.headers)
	copy(hs.Hash1[:], hash1)
	copy(hs.Hash2[:], computeSignHash2(hash1, nameHash, prefix))
	copy(hs.Hash3[:], computeSignHash3(fileHash, nameHash, prefix))

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

	if err := validateSignHashArgs(signVersion, gameType); err != nil {
		return nil, hs, err
	}

	opts.signHashVersion = signVersion
	opts.signHashGameType = gameType
	rewritePlan, opts, err := preparePackRequest(inputs, opts)
	if err != nil {
		return nil, hs, err
	}

	var result *PackResult
	err = writePackFileAtomically(outPath, func(f *os.File) error {
		details, err := rewriteArchiveDetailed(ctx, f, nil, rewritePlan, opts)
		if err != nil {
			return err
		}

		fileEnd, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return fmt.Errorf("seek end for hash: %w", err)
		}

		hash1, err := computeHash1ForFile(details, f, fileEnd, opts.SealedKey)
		if err != nil {
			return fmt.Errorf("hash1: %w", err)
		}

		nameHash := computeSignNameHash(details.entries)
		fileHash := details.fileHash
		if fileHash == nil {
			fileHash, err = computeSignFileHashFromReaderAt(f, details.entries, signVersion, gameType)
			if err != nil {
				return fmt.Errorf("file hash: %w", err)
			}
		}

		prefix := pboPrefixFromHeaders(details.headers)
		copy(hs.Hash1[:], hash1)
		copy(hs.Hash2[:], computeSignHash2(hash1, nameHash, prefix))
		copy(hs.Hash3[:], computeSignHash3(fileHash, nameHash, prefix))

		var trailer [21]byte
		copy(trailer[1:], hash1)
		if _, err := f.WriteAt(trailer[:], fileEnd); err != nil {
			return fmt.Errorf("write SHA1 trailer: %w", err)
		}
		result = details.packResult

		return nil
	})
	if err != nil {
		return nil, hs, err
	}

	return result, hs, nil
}

// preparePackRequest validates options and inputs before any output is changed.
func preparePackRequest(inputs []Input, opts PackOptions) ([]rewriteEntry, PackOptions, error) {
	if len(inputs) == 0 {
		return nil, opts, ErrEmptyInputs
	}

	opts.applyDefaults()
	rewritePlan, err := preparePackRewritePlan(inputs)
	if err != nil {
		return nil, opts, err
	}
	if err := validateHeaderProperties(opts.Headers); err != nil {
		return nil, opts, err
	}
	if err := validateRewritePlanPaths(rewritePlan); err != nil {
		return nil, opts, err
	}
	if _, err := newCompressMatcher(opts.CompressRules, opts.CompressMatcherOptions); err != nil {
		return nil, opts, fmt.Errorf("compile compress rules: %w", err)
	}

	return rewritePlan, opts, nil
}

// preparePackOutput resets truncatable outputs or verifies other outputs are empty at offset zero.
func preparePackOutput(out io.WriteSeeker) error {
	if out == nil {
		return ErrNilWriter
	}

	position, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("read output position: %w", err)
	}

	if truncater, ok := out.(interface{ Truncate(int64) error }); ok {
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek output start: %w", err)
		}
		if err := truncater.Truncate(0); err != nil {
			return fmt.Errorf("truncate output: %w", err)
		}
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("rewind truncated output: %w", err)
		}

		return nil
	}

	if position != 0 {
		return fmt.Errorf("output position %d: %w", position, ErrOutputPosition)
	}

	end, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("check output size: %w", err)
	}
	if end != 0 {
		_, restoreErr := out.Seek(position, io.SeekStart)
		return errors.Join(ErrOutputNotEmpty, restoreErr)
	}
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind empty output: %w", err)
	}

	return nil
}

// writePackFileAtomically builds a complete temporary archive before replacing the target.
func writePackFileAtomically(outPath string, build func(*os.File) error) (resultErr error) {
	directory := filepath.Dir(outPath)
	pattern := "." + filepath.Base(outPath) + ".tmp-*"
	tempFile, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return fmt.Errorf("create temporary PBO file: %w", err)
	}

	tempPath := tempFile.Name()
	installed := false
	defer func() {
		if tempFile != nil {
			resultErr = errors.Join(resultErr, tempFile.Close())
		}
		if installed {
			return
		}
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, fmt.Errorf("remove temporary PBO file: %w", err))
		}
	}()

	if err := build(tempFile); err != nil {
		return fmt.Errorf("write temporary PBO file: %w", err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("sync temporary PBO file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		tempFile = nil
		return fmt.Errorf("close temporary PBO file: %w", err)
	}

	tempFile = nil
	if err := replaceOutputFile(tempPath, outPath); err != nil {
		return err
	}

	installed = true
	return nil
}

// replaceOutputFile swaps a complete temporary file into place and restores the old target on failure.
func replaceOutputFile(tempPath string, outPath string) error {
	info, err := os.Lstat(outPath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(tempPath, outPath); err != nil {
			return fmt.Errorf("install PBO file: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect existing PBO file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("output path %q: %w", outPath, ErrInvalidOutputTarget)
	}
	if info.Mode().IsRegular() {
		if err := os.Chmod(tempPath, info.Mode().Perm()); err != nil {
			return fmt.Errorf("preserve PBO file permissions: %w", err)
		}
	}

	backupFile, err := os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".bak-*")
	if err != nil {
		return fmt.Errorf("reserve output backup: %w", err)
	}
	backupPath := backupFile.Name()
	if err := backupFile.Close(); err != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("close output backup placeholder: %w", err)
	}

	if err := os.Rename(outPath, backupPath); err != nil {
		cleanupErr := os.Remove(backupPath)
		return errors.Join(fmt.Errorf("move old PBO to backup: %w", err), cleanupErr)
	}
	if err := os.Rename(tempPath, outPath); err != nil {
		restoreErr := os.Rename(backupPath, outPath)
		if restoreErr != nil {
			return fmt.Errorf("install new PBO: %w (old PBO remains at %q; restore failed: %v)", err, backupPath, restoreErr)
		}
		return fmt.Errorf("install new PBO: %w", err)
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("remove previous PBO backup %q: %w", backupPath, err)
	}

	return nil
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
		if err := validateEntryPathWire(normalizedPath); err != nil {
			return nil, fmt.Errorf("input %d: %w", i, err)
		}

		sorted[i].Path = normalizedPath
	}

	slices.SortFunc(sorted, func(a, b Input) int {
		return strings.Compare(a.Path, b.Path)
	})

	if err := validateUniqueEntryPaths(sorted); err != nil {
		return nil, err
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

// validateRewritePlanPaths rejects paths that cannot be encoded as bounded
// NUL-terminated fields.
func validateRewritePlanPaths(rewritePlan []rewriteEntry) error {
	for i, item := range rewritePlan {
		if err := validateEntryPathWire(item.path); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
	}

	return nil
}

// validateEntryPathWire enforces the path constraints of the PBO index format.
func validateEntryPathWire(path string) error {
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("%w: path contains NUL", ErrInvalidEntryPath)
	}
	if len(path) > maxNameLen {
		return ErrFileNameTooLong
	}

	return nil
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
	selection compressionSelection,
	in Input,
	opts PackOptions,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	if !selection.candidate {
		return writeUncompressedPayload(dst, selection.source, in, currentOffset, copyBuf)
	}

	if selection.bounds == (compressionSizeBounds{}) {
		return writeCompressedCandidatePayload(dst, selection.source, in, opts, currentOffset, copyBuf)
	}

	return writeProfiledCandidatePayload(dst, selection.source, in, opts, selection.bounds, currentOffset, copyBuf)
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
	if err := validateHeaderProperties(opts.Headers); err != nil {
		return nil, err
	}
	if err := validateRewritePlanPaths(rewritePlan); err != nil {
		return nil, err
	}

	compressMatcher, err := newCompressMatcher(opts.CompressRules, opts.CompressMatcherOptions)
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
		if propertyKeyEqual(key, PropertyPrefix) {
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

	// Streaming file hash: tee sign-eligible payload bytes inline during write.
	// Disabled for sealed PBOs (on-disk bytes differ from written bytes after sealing).
	var (
		hfHasher    hash.Hash
		hfTeeWriter io.Writer // io.MultiWriter(w, hfHasher); created once and reused
		hfHashedAny bool
	)
	if opts.signHashVersion != 0 && !parseSealedKey(opts.SealedKey).enabled {
		hfHasher = sha1.New() //nolint:gosec
		hfTeeWriter = io.MultiWriter(w, hfHasher)
	}

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

		// Select write target: tee to file hasher for sign-eligible entries.
		entryDst := io.Writer(w)
		if hfHasher != nil {
			eligible, _ := shouldHashFileForSign(opts.signHashVersion, opts.signHashGameType, item.path)
			if eligible {
				entryDst = hfTeeWriter
				hfHashedAny = true
			}
		}

		if item.source != nil {
			if src == nil {
				return nil, ErrNilReader
			}

			record, err := writeSourcePackedPayload(entryDst, src, item.path, *item.source, currentOffset, copyBuf)
			if err != nil {
				return nil, err
			}

			appendWrittenEntry(item.path, record)

			continue
		}

		record, err := writeRewriteInputPayload(
			entryDst,
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

	var fileHash []byte
	if hfHasher != nil {
		if !hfHashedAny {
			if opts.signHashVersion == SignVersionV2 {
				_, _ = hfHasher.Write([]byte("nothing"))
			} else {
				_, _ = hfHasher.Write([]byte("gnihton"))
			}
		}
		fileHash = hfHasher.Sum(nil)
	}

	indexBuf := buildEntryIndexBlock(rewritePlan, written)

	if wa, ok := out.(io.WriterAt); ok {
		if n, err := wa.WriteAt(indexBuf, entriesStart); err != nil {
			return nil, fmt.Errorf("write entry index: %w", err)
		} else if n != len(indexBuf) {
			return nil, io.ErrShortWrite
		}
	} else {
		if _, err := out.Seek(entriesStart, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek entry index: %w", err)
		}
		if _, err := out.Write(indexBuf); err != nil {
			return nil, fmt.Errorf("write entry index: %w", err)
		}
	}

	if err := applySealedTransformToWriteSeeker(out, opts.SealedKey); err != nil {
		return nil, err
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
		entries:       entries,
		headers:       writtenHeaders,
		headerSection: encodeHeaderSection(header, writtenHeaders),
		indexBuf:      indexBuf,
		dataStart:     dataStart,
		fileHash:      fileHash,
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

	rc, err := openInputReader(*item.input)
	if err != nil {
		return writtenEntry{}, err
	}

	selection, selectErr := selectCompressionInput(opts, matcher, *item.input, rc)
	if selectErr != nil {
		_ = rc.Close()
		return writtenEntry{}, selectErr
	}

	record, writeErr := writeInputPayload(
		dst,
		selection,
		*item.input,
		opts,
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

	record.compressionCandidate = selection.candidate

	return record, nil
}

// shouldUseCompressionForInput reports whether input should enter compression candidate path.
func shouldUseCompressionForInput(opts PackOptions, matcher *compressMatcher, in Input) bool {
	if !opts.Compress {
		return false
	}

	if shouldSkipCompressBySizeHint(opts, in.SizeHint) {
		return false
	}

	if in.SizeHint > int64(^uint32(0)) {
		return false
	}
	if len(opts.CompressRules) == 0 {
		return autoCompressionMayApply(in.Path)
	}
	if matcher == nil {
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

	return (opts.MinCompressSize > 0 && sizeHint < int64(opts.MinCompressSize)) ||
		sizeHint > int64(opts.MaxCompressSize)
}

// writeCompressedCandidatePayload handles explicit-rule candidates with known sizes.
// Unknown-size and out-of-range explicit candidates are streamed raw.
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

// writeProfiledCandidatePayload applies format limits before invoking the compressor.
func writeProfiledCandidatePayload(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	bounds compressionSizeBounds,
	currentOffset uint32,
	copyBuf []byte,
) (writtenEntry, error) {
	maxEntrySize := int64(^uint32(0)) - int64(currentOffset)
	if !shouldUseProfiledInMemoryPath(opts, bounds, in.SizeHint, maxEntrySize) {
		return writeUncompressedPayload(dst, src, in, currentOffset, copyBuf)
	}

	return writeProfiledCandidatePayloadInMemory(dst, src, in, opts, bounds, currentOffset, copyBuf, maxEntrySize)
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

// shouldUseProfiledInMemoryPath keeps profile-excluded entries on the raw streaming path.
func shouldUseProfiledInMemoryPath(opts PackOptions, bounds compressionSizeBounds, sizeHint int64, maxEntrySize int64) bool {
	if bounds == (compressionSizeBounds{}) {
		return shouldUseInMemoryCompressPath(opts, sizeHint, maxEntrySize)
	}

	if sizeHint > maxEntrySize || sizeHint > int64(opts.MaxCompressSize) {
		return false
	}
	if bounds.max != 0 && sizeHint > int64(bounds.max) {
		return false
	}

	return true
}

// writeCompressedCandidatePayloadInMemory buffers at most MaxCompressSize+1 bytes before deciding whether to compress.
func writeCompressedCandidatePayloadInMemory(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	currentOffset uint32,
	copyBuf []byte,
	maxEntrySize int64,
) (writtenEntry, error) {
	return writeProfiledCandidatePayloadInMemory(dst, src, in, opts, compressionSizeBounds{}, currentOffset, copyBuf, maxEntrySize)
}

// writeProfiledCandidatePayloadInMemory buffers only bytes eligible under global and format limits.
func writeProfiledCandidatePayloadInMemory(
	dst io.Writer,
	src io.Reader,
	in Input,
	opts PackOptions,
	bounds compressionSizeBounds,
	currentOffset uint32,
	copyBuf []byte,
	maxEntrySize int64,
) (writtenEntry, error) {
	candidateLimit := min(int64(opts.MaxCompressSize), maxEntrySize)
	if bounds.max != 0 {
		candidateLimit = min(candidateLimit, int64(bounds.max))
	}
	chunks, rawSize, overLimit, err := readCompressionCandidate(src, candidateLimit, in.SizeHint)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("stream input %s: %w", in.Path, err)
	}

	if overLimit {
		if rawSize > maxEntrySize {
			return writtenEntry{}, fmt.Errorf("stream input %s: %w", in.Path, ErrSizeOverflow)
		}

		return writeRawCompressionFallback(dst, src, in, chunks, rawSize, currentOffset, maxEntrySize, copyBuf)
	}

	originalSize, err := checkedDataSize(in.Path, rawSize, currentOffset)
	if err != nil {
		return writtenEntry{}, err
	}

	record := writtenEntry{
		path:      in.Path,
		dataSize:  originalSize,
		mime:      MimeNil,
		timestamp: timeToUint32(in.ModTime),
	}
	if !shouldCompressByBounds(opts, bounds, originalSize) {
		if err := writeRawChunks(dst, chunks); err != nil {
			return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
		}

		return record, nil
	}

	var compressed []byte
	if len(chunks) == 1 {
		compressed, err = compressLZSS(chunks[0])
	} else {
		compressed, err = compressLZSSReader(&byteChunksReader{chunks: chunks})
	}
	if err != nil {
		return writtenEntry{}, fmt.Errorf("compress %s: %w", in.Path, err)
	}

	if int64(len(compressed)) >= rawSize {
		if err := writeRawChunks(dst, chunks); err != nil {
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
	if err := writePayloadBytes(dst, compressed); err != nil {
		return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
	}

	return record, nil
}

// readCompressionCandidate retains no more than limit+1 source bytes and reports whether the source exceeded limit.
func readCompressionCandidate(src io.Reader, limit int64, sizeHint int64) ([][]byte, int64, bool, error) {
	if src == nil {
		return nil, 0, false, ErrNilReader
	}
	if limit < 0 || limit == int64(^uint64(0)>>1) {
		return nil, 0, false, ErrSizeOverflow
	}

	readLimit := limit + 1
	chunkSize := int64(compressionCandidateChunkSize)
	initialChunkSize := chunkSize
	if sizeHint > 0 && sizeHint < chunkSize {
		initialChunkSize = sizeHint
	}
	chunks := make([][]byte, 0)
	var total int64

	emptyReads := 0
	for total < readLimit {
		var firstByte byte
		hasFirstByte := false
		if total > 0 {
			for {
				var probe [1]byte
				n, err := src.Read(probe[:])
				if n > 0 {
					emptyReads = 0
					firstByte = probe[0]
					hasFirstByte = true
					if err != nil && err != io.EOF {
						return nil, total + 1, false, err
					}

					if err == io.EOF {
						chunks = append(chunks, []byte{firstByte})
						total++
						return chunks, total, total > limit, nil
					}

					break
				}

				if err == io.EOF {
					return chunks, total, total > limit, nil
				}
				if err != nil {
					return nil, total, false, err
				}

				emptyReads++
				if emptyReads > 100 {
					return nil, total, false, io.ErrNoProgress
				}
			}
		}

		currentChunkSize := chunkSize
		if total == 0 {
			currentChunkSize = initialChunkSize
		}
		currentChunkSize = min(currentChunkSize, readLimit-total)
		chunk := make([]byte, int(currentChunkSize))
		filled := 0
		if hasFirstByte {
			chunk[0] = firstByte
			filled = 1
		}

		for filled < len(chunk) {
			n, err := src.Read(chunk[filled:])
			filled += n
			if n > 0 {
				emptyReads = 0
			}

			if err != nil {
				if err != io.EOF {
					return nil, total + int64(filled), false, err
				}

				if filled > 0 {
					chunks = append(chunks, chunk[:filled])
					total += int64(filled)
				}

				return chunks, total, total > limit, nil
			}

			if n == 0 {
				emptyReads++
				if emptyReads > 100 {
					return nil, total + int64(filled), false, io.ErrNoProgress
				}
			}
		}

		chunks = append(chunks, chunk)
		total += int64(filled)
	}

	return chunks, total, true, nil
}

// writeRawCompressionFallback writes the buffered over-limit prefix and streams the remaining source raw.
func writeRawCompressionFallback(
	dst io.Writer,
	src io.Reader,
	in Input,
	prefix [][]byte,
	prefixSize int64,
	currentOffset uint32,
	maxEntrySize int64,
	copyBuf []byte,
) (writtenEntry, error) {
	if err := writeRawChunks(dst, prefix); err != nil {
		return writtenEntry{}, fmt.Errorf("write payload %s: %w", in.Path, err)
	}

	remaining := maxEntrySize - prefixSize
	streamed, err := copyPayloadBounded(dst, src, remaining, copyBuf)
	if err != nil {
		return writtenEntry{}, fmt.Errorf("stream input %s: %w", in.Path, err)
	}

	total := prefixSize + streamed
	dataSize, err := checkedDataSize(in.Path, total, currentOffset)
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

// writeRawChunks writes retained candidate bytes without creating another payload-sized allocation.
func writeRawChunks(dst io.Writer, chunks [][]byte) error {
	for _, chunk := range chunks {
		if err := writePayloadBytes(dst, chunk); err != nil {
			return err
		}
	}

	return nil
}

// writePayloadBytes writes a complete buffered payload and detects short writes.
func writePayloadBytes(dst io.Writer, payload []byte) error {
	n, err := dst.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}

	return nil
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
		key := archiveLookupKey(in.Path)
		if existing, ok := seen[key]; ok {
			return fmt.Errorf("%w: %q conflicts with %q", ErrDuplicateEntryPath, in.Path, existing)
		}

		seen[key] = in.Path
	}

	return nil
}

// buildEntryIndexBlock serializes the full entry index block
// (paths + 20-byte field blocks + sentinel) into one contiguous buffer.
// Caller writes it in a single operation to replace  previous per-entry seek/write patch loop.
func buildEntryIndexBlock(plan []rewriteEntry, written []writtenEntry) []byte {
	var n int
	for _, item := range plan {
		n += len(item.path) + 1 + 20
	}
	n += 1 + 20 // sentinel: null name + 20 zero fields (zero-init by make)

	buf := make([]byte, n)
	off := 0
	for i, item := range plan {
		off += copy(buf[off:], item.path)
		buf[off] = 0
		off++
		record := written[i]
		binary.LittleEndian.PutUint32(buf[off+0:off+4], uint32(record.mime))
		binary.LittleEndian.PutUint32(buf[off+4:off+8], record.originalSize)
		// Common tooling emits zero in index offset and derives offsets sequentially.
		binary.LittleEndian.PutUint32(buf[off+8:off+12], 0)
		binary.LittleEndian.PutUint32(buf[off+12:off+16], record.timestamp)
		binary.LittleEndian.PutUint32(buf[off+16:off+20], record.dataSize)
		off += 20
	}

	buf[off] = 0 // sentinel null name; remaining 20 bytes stay zero from make
	return buf
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

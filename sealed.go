// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

const (
	// sealedBlockSize is a fixed transform block size.
	sealedBlockSize = 0x1000
	// sealedKeySize is a fixed sealed key size in bytes.
	sealedKeySize = 16
	// sealedTrailerSize is size of optional SHA1 trailer (0x00 + sha1).
	sealedTrailerSize = 21
)

// sealedRC4State holds state for one transformed block.
type sealedRC4State struct {
	// index1 is first permutation index.
	index1 uint8
	// index2 is second permutation index.
	index2 uint8
	// state stores 256-byte permutation.
	state [256]byte
}

// sealedKey stores validated key bytes and enabled state.
type sealedKey struct {
	// bytes stores 16-byte sealed key.
	bytes SealedKey
	// enabled reports whether sealed mode is active.
	enabled bool
}

// sealedLayout holds precomputed transform layout derived from archive shape.
type sealedLayout struct {
	// headerSkip is end offset of untransformed header+header-pairs area.
	headerSkip int64
	// transformSize is archive region size affected by transform (without trailer).
	transformSize int64
	// seed is transform seed derived from transformSize.
	seed uint32
}

// sealedReaderAt wraps source ReaderAt and decodes transformed bytes on demand.
type sealedReaderAt struct {
	// source is underlying encoded archive bytes.
	source io.ReaderAt
	// layout stores transform geometry for this archive.
	layout sealedLayout
	// key stores validated transform key bytes.
	key sealedKey
}

// prepareReaderAtWithSealedOptions wraps source reader with on-demand sealed decode when enabled.
func prepareReaderAtWithSealedOptions(ra io.ReaderAt, size int64, sealedKeyValue *SealedKey) (io.ReaderAt, error) {
	if ra == nil {
		return nil, ErrNilReader
	}

	key := parseSealedKey(sealedKeyValue)

	if !key.enabled {
		return ra, nil
	}

	layout, err := buildSealedLayout(ra, size, true)
	if err != nil {
		return nil, err
	}

	return &sealedReaderAt{
		source: ra,
		layout: layout,
		key:    key,
	}, nil
}

// ReadAt reads bytes from source and decodes transformed ranges in-place.
func (s *sealedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.source.ReadAt(p, off)
	if n <= 0 {
		return n, err
	}

	applySealedRangeInPlace(p[:n], off, s.layout, s.key)

	return n, err
}

// applySealedTransformToWriteSeeker applies in-place sealed transform for packed output.
func applySealedTransformToWriteSeeker(out io.WriteSeeker, sealedKeyValue *SealedKey) error {
	if out == nil {
		return ErrNilWriter
	}

	ra, ok := out.(io.ReaderAt)
	if !ok {
		return ErrReaderAtRequired
	}

	wa, ok := out.(io.WriterAt)
	if !ok {
		return ErrWriterAtRequired
	}

	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek output end for sealed transform: %w", err)
	}

	if err := applySealedTransformToReadWriteAt(ra, wa, size, sealedKeyValue, false); err != nil {
		return err
	}

	if _, err := out.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek output end after sealed transform: %w", err)
	}

	return nil
}

// ToggleSealedInPlace toggles sealed transform for an existing archive stream.
//
// This operation is symmetric: applying it twice with the same key restores
// the original bytes.
func ToggleSealedInPlace(out io.ReadWriteSeeker, sealedKeyValue *SealedKey) error {
	if out == nil {
		return ErrNilWriter
	}

	ra, ok := out.(io.ReaderAt)
	if !ok {
		return ErrReaderAtRequired
	}

	wa, ok := out.(io.WriterAt)
	if !ok {
		return ErrWriterAtRequired
	}

	size, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seek output end for sealed toggle: %w", err)
	}

	if err := applySealedTransformToReadWriteAt(ra, wa, size, sealedKeyValue, true); err != nil {
		return err
	}

	if _, err := out.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek output end after sealed toggle: %w", err)
	}

	return nil
}

// applySealedTransformToReadWriteAt transforms archive bytes in place.
func applySealedTransformToReadWriteAt(
	ra io.ReaderAt,
	wa io.WriterAt,
	size int64,
	sealedKeyValue *SealedKey,
	detectTrailer bool,
) error {
	key := parseSealedKey(sealedKeyValue)

	if !key.enabled {
		return nil
	}

	layout, err := buildSealedLayout(ra, size, detectTrailer)
	if err != nil {
		return err
	}

	var segment [sealedBlockSize]byte
	err = forEachSealedSegment(layout, func(segmentStart int64, segmentEnd int64, streamPos uint32) error {
		n := int(segmentEnd - segmentStart)
		buf := segment[:n]
		if err := readFullAt(ra, buf, segmentStart); err != nil {
			return fmt.Errorf("read sealed segment: %w", err)
		}

		state := newSealedRC4StateForStreamPos(key, layout.seed, streamPos)
		state.swapIndices()
		state.apply(buf)

		if err := writeFullAt(wa, buf, segmentStart); err != nil {
			return fmt.Errorf("write sealed segment: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

// parseSealedKey converts optional sealed key to internal key representation.
func parseSealedKey(value *SealedKey) sealedKey {
	var key sealedKey
	if value == nil {
		return key
	}

	key.bytes = *value
	key.enabled = true

	return key
}

// buildSealedLayout resolves transform region/seed from archive metadata.
func buildSealedLayout(ra io.ReaderAt, size int64, detectTrailer bool) (sealedLayout, error) {
	var layout sealedLayout
	if ra == nil {
		return layout, ErrNilReader
	}

	if size < headerSize {
		return layout, fmt.Errorf("%w: short header", ErrInvalidHeader)
	}

	transformSize := size
	if detectTrailer {
		if trailerSize, hasTrailer, err := detectSealedTrailerSize(ra, size); err != nil {
			return layout, err
		} else if hasTrailer {
			transformSize -= trailerSize
		}
	}

	if transformSize < headerSize || uint64(transformSize) > uint64(math.MaxUint32) {
		return layout, ErrSizeOverflow
	}

	_, _, tableOffset, err := parseHeaderSection(ra)
	if err != nil {
		return layout, err
	}

	if tableOffset < 0 || tableOffset > transformSize {
		return layout, fmt.Errorf("%w: sealed header offset is out of range", ErrInvalidHeader)
	}

	if tableOffset >= sealedBlockSize {
		return layout, fmt.Errorf("%w: sealed header offset exceeds first transform block", ErrInvalidHeader)
	}

	layout.headerSkip = tableOffset
	layout.transformSize = transformSize
	seedValue, err := checkedInt64ToUint32(transformSize)
	if err != nil {
		return layout, err
	}

	layout.seed = sealedSeed(seedValue)

	return layout, nil
}

// detectSealedTrailerSize checks optional tail pattern used by SHA1 trailer.
func detectSealedTrailerSize(ra io.ReaderAt, size int64) (int64, bool, error) {
	if size < sealedTrailerSize {
		return 0, false, nil
	}

	var tail [sealedTrailerSize]byte
	if _, err := ra.ReadAt(tail[:], size-sealedTrailerSize); err != nil {
		return 0, false, fmt.Errorf("read trailer probe: %w", err)
	}

	return sealedTrailerSize, tail[0] == 0x00, nil
}

// applySealedTransformInPlace transforms archive bytes in place.
//
//nolint:unused // Used by tests/benchmarks for direct roundtrip verification.
func applySealedTransformInPlace(data []byte, sealedKeyValue *SealedKey) error {
	key := parseSealedKey(sealedKeyValue)

	if !key.enabled {
		return nil
	}

	layout, err := buildSealedLayout(bytes.NewReader(data), int64(len(data)), true)
	if err != nil {
		return err
	}

	applySealedRangeInPlace(data, 0, layout, key)

	return nil
}

// applySealedRangeInPlace transforms only overlapping transformed region for byte range.
func applySealedRangeInPlace(data []byte, offset int64, layout sealedLayout, key sealedKey) {
	if !key.enabled || len(data) == 0 {
		return
	}

	rangeStart := maxInt64(offset, layout.headerSkip)
	rangeEnd := minInt64(offset+int64(len(data)), layout.transformSize)
	if rangeStart >= rangeEnd {
		return
	}

	cur := rangeStart
	for cur < rangeEnd {
		segmentStart, segmentEnd, streamPos := sealedSegmentAt(layout, cur)
		if segmentEnd > rangeEnd {
			segmentEnd = rangeEnd
		}

		state := newSealedRC4StateForStreamPos(key, layout.seed, streamPos)
		state.swapIndices()
		state.discard(int(cur - segmentStart))

		localStart := int(cur - offset)
		localEnd := int(segmentEnd - offset)
		state.apply(data[localStart:localEnd])

		cur = segmentEnd
	}
}

// forEachSealedSegment iterates transform segments in file order.
func forEachSealedSegment(layout sealedLayout, fn func(segmentStart int64, segmentEnd int64, streamPos uint32) error) error {
	if layout.transformSize <= layout.headerSkip {
		return nil
	}

	firstEnd := minInt64(sealedBlockSize, layout.transformSize)
	if layout.headerSkip < firstEnd {
		if err := fn(layout.headerSkip, firstEnd, 0); err != nil {
			return err
		}
	}

	segmentStart := int64(sealedBlockSize)
	for segmentStart < layout.transformSize {
		segmentEnd := min(segmentStart+sealedBlockSize, layout.transformSize)
		streamPos, err := checkedInt64ToUint32(segmentStart)
		if err != nil {
			return err
		}

		if err := fn(segmentStart, segmentEnd, streamPos); err != nil {
			return err
		}

		segmentStart += sealedBlockSize
	}

	return nil
}

// sealedSegmentAt resolves transform segment boundaries for a file offset.
func sealedSegmentAt(layout sealedLayout, pos int64) (segmentStart int64, segmentEnd int64, streamPos uint32) {
	if pos < sealedBlockSize {
		segmentStart = layout.headerSkip
		segmentEnd = minInt64(sealedBlockSize, layout.transformSize)

		return segmentStart, segmentEnd, 0
	}

	segmentStart = (pos / sealedBlockSize) * sealedBlockSize
	segmentEnd = minInt64(segmentStart+sealedBlockSize, layout.transformSize)
	streamPos, err := checkedInt64ToUint32(segmentStart)
	if err != nil {
		return segmentStart, segmentEnd, 0
	}

	return segmentStart, segmentEnd, streamPos
}

// readFullAt reads all bytes into destination from ReaderAt at given offset.
func readFullAt(ra io.ReaderAt, dst []byte, off int64) error {
	for len(dst) > 0 {
		n, err := ra.ReadAt(dst, off)
		off += int64(n)
		dst = dst[n:]

		if err == nil {
			continue
		}

		if err == io.EOF && len(dst) == 0 {
			return nil
		}

		return err
	}

	return nil
}

// writeFullAt writes all bytes from source into WriterAt at given offset.
func writeFullAt(wa io.WriterAt, src []byte, off int64) error {
	for len(src) > 0 {
		n, err := wa.WriteAt(src, off)
		off += int64(n)
		src = src[n:]

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrShortWrite
		}
	}

	return nil
}

// sealedSeed computes initial stream seed from archive size.
func sealedSeed(size uint32) uint32 {
	leftShift := uint((8 - (size & 7)) & 7)
	rightShift := uint((size >> 3) & 7)
	mixed := (size << leftShift) | (size >> rightShift)

	return size ^ mixed
}

// sealedInitIterations computes RC4 warmup iteration count for one block.
func sealedInitIterations(curPos uint32, seed uint32) int {
	procSeed := curPos ^ seed
	r := sealedRand(&procSeed)
	r *= float32(sealedBlockSize / 16)
	r -= 0.5

	tmp := r + 12582912.0
	tmpiBits := math.Float32bits(tmp)
	tmpiBits &= 0x7FFFFF
	tmpiBits += 0xFFC00000
	tmpiBits += 256
	tmpi := int64(tmpiBits)
	if tmpiBits >= 0x80000000 {
		tmpi -= 1 << 32
	}

	if tmpi < 256 {
		tmpi = 256
	} else if tmpi > 511 {
		tmpi = 511
	}

	return int(tmpi)
}

// sealedRand updates seed and returns pseudo-random float value.
func sealedRand(seed *uint32) float32 {
	const (
		multiplier = uint32(1043968403)
		additive   = uint32(12345)
		mask       = uint32(0x7FFFFFFF)
		scaleBits  = uint32(0x30000000)
	)

	*seed = (additive - (multiplier * *seed)) & mask

	return float32(*seed) * math.Float32frombits(scaleBits)
}

// newSealedRC4StateForStreamPos initializes RC4-like state for one stream position.
func newSealedRC4StateForStreamPos(key sealedKey, seed uint32, streamPos uint32) sealedRC4State {
	mixed := key.bytes
	mask := streamPos ^ (^seed)

	for i := 0; i < sealedKeySize; i += 4 {
		word := binary.LittleEndian.Uint32(mixed[i : i+4])
		word ^= mask
		binary.LittleEndian.PutUint32(mixed[i:i+4], word)
	}

	return newSealedRC4State(mixed[:], sealedInitIterations(streamPos, seed))
}

// newSealedRC4State initializes one RC4-like state with warmup.
func newSealedRC4State(key []byte, warmup int) sealedRC4State {
	var s sealedRC4State
	for i := range 256 {
		s.state[i] = byte(i)
	}

	var j uint8
	for i := range 256 {
		j += key[i%len(key)] + s.state[i]
		s.state[i], s.state[j] = s.state[j], s.state[i]
	}

	for range warmup {
		s.index1++
		s.index2 += s.state[s.index1]
		s.state[s.index1], s.state[s.index2] = s.state[s.index2], s.state[s.index1]
	}

	return s
}

// swapIndices swaps internal RC4 indices before stream stage.
func (s *sealedRC4State) swapIndices() {
	s.index1, s.index2 = s.index2, s.index1
}

// discard advances RC4 state by n bytes without writing output.
func (s *sealedRC4State) discard(n int) {
	for range n {
		s.index1++
		s.index2 += s.state[s.index1]
		s.state[s.index1], s.state[s.index2] = s.state[s.index2], s.state[s.index1]
		_ = s.state[s.state[s.index1]+s.state[s.index2]]
	}
}

// apply XOR-transforms payload bytes in place using RC4-like stream.
func (s *sealedRC4State) apply(data []byte) {
	for i := range data {
		s.index1++
		s.index2 += s.state[s.index1]
		s.state[s.index1], s.state[s.index2] = s.state[s.index2], s.state[s.index1]
		k := s.state[s.index1] + s.state[s.index2]
		data[i] ^= s.state[k]
	}
}

// minInt64 returns smaller of two int64 values.
func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}

	return b
}

// maxInt64 returns larger of two int64 values.
func maxInt64(a int64, b int64) int64 {
	if a > b {
		return a
	}

	return b
}

// checkedInt64ToUint32 converts int64 to uint32 with bounds checking.
func checkedInt64ToUint32(v int64) (uint32, error) {
	if v < 0 || uint64(v) > uint64(math.MaxUint32) {
		return 0, ErrSizeOverflow
	}

	return uint32(v), nil
}

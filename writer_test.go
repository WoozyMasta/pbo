// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pathrules"
)

func TestShouldUseCompressionForInput(t *testing.T) {
	t.Parallel()

	opts := PackOptions{
		MinCompressSize: 100,
		MaxCompressSize: 1000,
	}
	opts.applyDefaults()

	matcher, err := newCompressMatcher(includeRules("*.paa"), pathrules.MatcherOptions{
		CaseInsensitive: true,
		DefaultAction:   pathrules.ActionExclude,
	})
	if err != nil {
		t.Fatalf("newCompressMatcher: %v", err)
	}

	inputs := []Input{
		{Path: "data/a.txt", SizeHint: 256},
		{Path: "data/b.paa", SizeHint: 50},
		{Path: "data/c.paa", SizeHint: 0},
		{Path: "data/d.paa", SizeHint: 200},
	}

	want := []bool{false, false, true, true}
	if len(inputs) != len(want) {
		t.Fatalf("inputs len=%d, want %d", len(inputs), len(want))
	}

	hasCandidates := false
	for i := range want {
		got := shouldUseCompressionForInput(opts, matcher, inputs[i])
		if got != want[i] {
			t.Fatalf("shouldUseCompressionForInput[%d]=%v, want %v", i, got, want[i])
		}

		if got {
			hasCandidates = true
		}
	}

	if !hasCandidates {
		t.Fatal("expected at least one compression candidate")
	}
}

func TestCopyPayloadBounded(t *testing.T) {
	t.Parallel()

	t.Run("exact limit", func(t *testing.T) {
		t.Parallel()

		var dst bytes.Buffer
		src := bytes.NewReader([]byte("abc"))
		written, err := copyPayloadBounded(&dst, src, 3, make([]byte, 2))
		if err != nil {
			t.Fatalf("copyPayloadBounded: %v", err)
		}
		if written != 3 {
			t.Fatalf("written=%d, want 3", written)
		}
		if got := dst.String(); got != "abc" {
			t.Fatalf("dst=%q, want %q", got, "abc")
		}
	})

	t.Run("overflow", func(t *testing.T) {
		t.Parallel()

		var dst bytes.Buffer
		src := bytes.NewReader([]byte("abcdef"))
		written, err := copyPayloadBounded(&dst, src, 3, make([]byte, 2))
		if !errors.Is(err, ErrSizeOverflow) {
			t.Fatalf("expected ErrSizeOverflow, got %v", err)
		}
		if written != 3 {
			t.Fatalf("written=%d, want 3", written)
		}
		if got := dst.String(); got != "abc" {
			t.Fatalf("dst=%q, want %q", got, "abc")
		}
	})
}

func TestShouldUseInMemoryCompressPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		opts     PackOptions
		sizeHint int64
		limit    int64
		want     bool
	}{
		{name: "unknown", opts: PackOptions{MaxCompressSize: 1024}, sizeHint: 0, limit: 100, want: false},
		{name: "negative", opts: PackOptions{MaxCompressSize: 1024}, sizeHint: -1, limit: 100, want: false},
		{name: "too large hint", opts: PackOptions{MaxCompressSize: 1024}, sizeHint: 1025, limit: 1 << 30, want: false},
		{name: "beyond entry limit", opts: PackOptions{MaxCompressSize: 1024}, sizeHint: 128, limit: 127, want: false},
		{name: "small known", opts: PackOptions{MaxCompressSize: 1024}, sizeHint: 128, limit: 1 << 30, want: true},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := shouldUseInMemoryCompressPath(tc.opts, tc.sizeHint, tc.limit)
			if got != tc.want {
				t.Fatalf("shouldUseInMemoryCompressPath(%+v, %d, %d) = %v, want %v", tc.opts, tc.sizeHint, tc.limit, got, tc.want)
			}
		})
	}
}

func TestPack_CompressEnabledNoMatchKeepsUncompressed(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	payload := bytes.Repeat([]byte("x"), 4096)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{Compress: includeRules("*.paa")})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if entries[0].IsCompressed() {
		t.Fatal("entry must stay uncompressed when compress patterns do not match")
	}
}

func TestPack_RejectsDuplicateEntryPathsCaseInsensitive(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	openFn := func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader([]byte("ok"))), nil
	}

	inputs := []Input{
		{Path: "data/a.txt", Open: openFn},
		{Path: "data/A.TXT", Open: openFn},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{})
	if !errors.Is(err, ErrDuplicateEntryPath) {
		t.Fatalf("expected ErrDuplicateEntryPath, got %v", err)
	}
}

func TestPack_RejectsInvalidNormalizedEntryPath(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	inputs := []Input{
		{
			Path: "/",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("ok"))), nil
			},
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{})
	if !errors.Is(err, ErrInvalidEntryPath) {
		t.Fatalf("expected ErrInvalidEntryPath, got %v", err)
	}
}

func TestPack_UnknownSizeHintKeepsRaw(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	payload := bytes.Repeat([]byte("x"), 64*1024)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: 0, // unknown size forces non-in-memory candidate path
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{
		Compress: includeRules("*"),
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if entries[0].IsCompressed() {
		t.Fatal("entry must stay uncompressed when size is unknown")
	}
}

func TestPack_KnownSmallSizeCompresses(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	payload := bytes.Repeat([]byte("x"), 64*1024)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{
		Compress: includeRules("*"),
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if !entries[0].IsCompressed() {
		t.Fatal("entry must be compressed for known small size")
	}
}

func TestPack_UnknownSizeHintStaysRawWhenCompressEnabled(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	payload := bytes.Repeat([]byte("x"), 64*1024)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: 0, // unknown size is always raw in main pack flow
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{Compress: includeRules("*")})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if entries[0].IsCompressed() {
		t.Fatal("entry must stay uncompressed when size is unknown")
	}
}

func TestPack_KnownSizeOverMaxCompressSizeStaysRaw(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	payload := bytes.Repeat([]byte("x"), 64*1024)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{
		Compress:        includeRules("*"),
		MinCompressSize: 1,
		MaxCompressSize: 1024, // smaller than payload
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if entries[0].IsCompressed() {
		t.Fatal("entry must stay uncompressed when known size is above MaxCompressSize")
	}
}

// TestCompressCandidate_FalseLowSizeHintFallsBackToRaw verifies the hard candidate cap and one-open fallback.
func TestCompressCandidate_FalseLowSizeHintFallsBackToRaw(t *testing.T) {
	const maxCompressSize = 1024
	payload := bytes.Repeat([]byte("payload"), 1024)
	src := &observedReadReader{reader: bytes.NewReader(payload)}
	dst := &observedWriteBuffer{src: src}
	opts := PackOptions{
		MinCompressSize: 1,
		MaxCompressSize: maxCompressSize,
	}
	opts.applyDefaults()

	record, err := writeCompressedCandidatePayload(
		dst,
		src,
		Input{Path: "false-low.txt", SizeHint: 1},
		opts,
		0,
		make([]byte, 32*1024),
	)
	if err != nil {
		t.Fatalf("writeCompressedCandidatePayload: %v", err)
	}
	if src.read != int64(len(payload)) {
		t.Fatalf("read %d bytes, want %d", src.read, len(payload))
	}
	if dst.firstWriteRead != maxCompressSize+1 {
		t.Fatalf("first write after %d bytes read, want %d", dst.firstWriteRead, maxCompressSize+1)
	}
	if !bytes.Equal(dst.data.Bytes(), payload) {
		t.Fatal("raw fallback output differs from source")
	}
	if record.mime != MimeNil || record.dataSize != uint32(len(payload)) || record.originalSize != 0 {
		t.Fatalf("fallback metadata = %+v, want uncompressed entry", record)
	}
}

// TestCompressCandidateBoundaries checks exact-limit, over-limit, and incompressible payload decisions.
func TestCompressCandidateBoundaries(t *testing.T) {
	const maxCompressSize = 1024
	incompressible := make([]byte, maxCompressSize)
	rng := rand.New(rand.NewSource(42))
	if _, err := rng.Read(incompressible); err != nil {
		t.Fatalf("generate incompressible input: %v", err)
	}

	testCases := []struct {
		name       string
		payload    []byte
		sizeHint   int64
		wantMime   MimeType
		wantOrigSz uint32
	}{
		{
			name:       "exact max compressible",
			payload:    bytes.Repeat([]byte("x"), maxCompressSize),
			sizeHint:   maxCompressSize,
			wantMime:   MimeCompress,
			wantOrigSz: maxCompressSize,
		},
		{
			name:     "max plus one",
			payload:  bytes.Repeat([]byte("x"), maxCompressSize+1),
			sizeHint: 1,
			wantMime: MimeNil,
		},
		{
			name:     "incompressible within max",
			payload:  incompressible,
			sizeHint: maxCompressSize,
			wantMime: MimeNil,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			opts := PackOptions{MinCompressSize: 1, MaxCompressSize: maxCompressSize}
			opts.applyDefaults()
			var dst bytes.Buffer
			record, err := writeCompressedCandidatePayload(
				&dst,
				bytes.NewReader(tc.payload),
				Input{Path: "boundary.bin", SizeHint: tc.sizeHint},
				opts,
				0,
				make([]byte, 32*1024),
			)
			if err != nil {
				t.Fatalf("writeCompressedCandidatePayload: %v", err)
			}
			if record.mime != tc.wantMime {
				t.Fatalf("mime = %v, want %v", record.mime, tc.wantMime)
			}
			if record.originalSize != tc.wantOrigSz {
				t.Fatalf("original size = %d, want %d", record.originalSize, tc.wantOrigSz)
			}
			if tc.wantMime == MimeNil && !bytes.Equal(dst.Bytes(), tc.payload) {
				t.Fatal("raw output differs from source")
			}
		})
	}
}

// TestCompressCandidateAcrossChunksRoundTripsDeterministically verifies multi-chunk stream compression.
func TestCompressCandidateAcrossChunksRoundTripsDeterministically(t *testing.T) {
	payload := bytes.Repeat([]byte("chunk-boundary-data-"), 150_000)
	opts := PackOptions{MinCompressSize: 1, MaxCompressSize: 4 << 20}
	opts.applyDefaults()
	var dst bytes.Buffer

	record, err := writeCompressedCandidatePayload(
		&dst,
		bytes.NewReader(payload),
		Input{Path: "multi-chunk.bin", SizeHint: int64(len(payload))},
		opts,
		0,
		make([]byte, 32*1024),
	)
	if err != nil {
		t.Fatalf("writeCompressedCandidatePayload: %v", err)
	}
	if record.mime != MimeCompress || record.originalSize != uint32(len(payload)) {
		t.Fatalf("record = %+v, want compressed entry of %d bytes", record, len(payload))
	}

	var decoded bytes.Buffer
	if _, err := lzss.DecompressToWriter(&decoded, bytes.NewReader(dst.Bytes()), len(payload), nil); err != nil {
		t.Fatalf("DecompressToWriter: %v", err)
	}
	if !bytes.Equal(decoded.Bytes(), payload) {
		t.Fatal("multi-chunk decompression differs from source")
	}

	var repeated bytes.Buffer
	if _, err := writeCompressedCandidatePayload(
		&repeated,
		bytes.NewReader(payload),
		Input{Path: "multi-chunk.bin", SizeHint: int64(len(payload))},
		opts,
		0,
		make([]byte, 32*1024),
	); err != nil {
		t.Fatalf("repeat writeCompressedCandidatePayload: %v", err)
	}
	if !bytes.Equal(repeated.Bytes(), dst.Bytes()) {
		t.Fatal("multi-chunk compression output is not deterministic")
	}
}

// TestCompressCandidateRejectsSourceBeyondRemainingPBOAddressSpace verifies offset-bound enforcement.
func TestCompressCandidateRejectsSourceBeyondRemainingPBOAddressSpace(t *testing.T) {
	const remaining = 100
	payload := bytes.Repeat([]byte("x"), remaining+1)
	src := &observedReadReader{reader: bytes.NewReader(payload)}
	var dst bytes.Buffer
	opts := PackOptions{MinCompressSize: 1, MaxCompressSize: 1024}
	opts.applyDefaults()

	_, err := writeCompressedCandidatePayload(
		&dst,
		src,
		Input{Path: "too-large.bin", SizeHint: 1},
		opts,
		^uint32(0)-remaining,
		make([]byte, 32*1024),
	)
	if !errors.Is(err, ErrSizeOverflow) {
		t.Fatalf("expected ErrSizeOverflow, got %v", err)
	}
	if src.read != remaining+1 {
		t.Fatalf("read %d bytes, want %d-byte overflow probe", src.read, remaining+1)
	}
	if dst.Len() != 0 {
		t.Fatalf("wrote %d bytes before address-space overflow", dst.Len())
	}
}

// TestPack_AdvisorySizeHintsDoNotRejectActualSmallArchive verifies actual streamed bytes govern PBO size.
func TestPack_AdvisorySizeHintsDoNotRejectActualSmallArchive(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.pbo")
	openSource := func(data []byte) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
	}
	inputs := []Input{
		{Path: "a.bin", Open: openSource([]byte("a")), SizeHint: maxPBOData/2 + 1},
		{Path: "b.bin", Open: openSource([]byte("b")), SizeHint: maxPBOData/2 + 1},
	}

	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	if _, err := Pack(t.Context(), f, inputs, PackOptions{}); err != nil {
		_ = f.Close()
		t.Fatalf("Pack rejected actual small payloads: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close output: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if got := len(r.Entries()); got != len(inputs) {
		t.Fatalf("entries = %d, want %d", got, len(inputs))
	}
}

// observedReadReader counts bytes consumed from its wrapped source.
type observedReadReader struct {
	// reader is the wrapped source.
	reader io.Reader
	// read is the total number of bytes consumed from the source.
	read int64
}

// Read forwards bytes while tracking source consumption.
func (r *observedReadReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)

	return n, err
}

// observedWriteBuffer records source consumption when the first write begins.
type observedWriteBuffer struct {
	// src is the source whose read count is sampled at the first write.
	src *observedReadReader
	// data stores all bytes written to the buffer.
	data bytes.Buffer
	// firstWriteRead records how much source data was consumed before writing began.
	firstWriteRead int64
}

// Write records the first-write boundary and stores all written bytes.
func (w *observedWriteBuffer) Write(p []byte) (int, error) {
	if w.firstWriteRead == 0 {
		w.firstWriteRead = w.src.read
	}

	return w.data.Write(p)
}

func TestPack_TelemetryAndOnEntryDone(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}
	defer func() { _ = f.Close() }()

	compressible := bytes.Repeat([]byte("x"), 64*1024)
	rawData := []byte("raw-content")
	inputs := []Input{
		{
			Path: "c.bin",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(rawData)), nil
			},
			SizeHint: int64(len(rawData)),
		},
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(compressible)), nil
			},
			SizeHint: int64(len(compressible)),
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(compressible)), nil
			},
			SizeHint: 0, // unknown size forces raw write in current pack flow
		},
	}

	progress := make([]PackEntryProgress, 0, len(inputs))
	res, err := Pack(context.Background(), f, inputs, PackOptions{
		Compress:        includeRules("*.txt"),
		MinCompressSize: 1,
		OnEntryDone: func(entry PackEntryProgress) {
			progress = append(progress, entry)
		},
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	if res.WrittenEntries != len(inputs) {
		t.Fatalf("written_entries=%d, want %d", res.WrittenEntries, len(inputs))
	}
	if res.CompressedEntries != 1 {
		t.Fatalf("compressed_entries=%d, want 1", res.CompressedEntries)
	}
	if res.SkippedCompressionEntries != 1 {
		t.Fatalf("skipped_compression_entries=%d, want 1", res.SkippedCompressionEntries)
	}
	if res.RawBytes+res.CompressedBytes != res.DataSize {
		t.Fatalf("raw+compressed=%d, data_size=%d", res.RawBytes+res.CompressedBytes, res.DataSize)
	}
	if res.Duration <= 0 {
		t.Fatalf("duration=%s, want > 0", res.Duration)
	}

	if len(progress) != len(inputs) {
		t.Fatalf("on_entry_done events=%d, want %d", len(progress), len(inputs))
	}

	compressedCount := 0
	candidateCount := 0
	for _, e := range progress {
		if e.CompressionCandidate {
			candidateCount++
		}

		if e.Compressed {
			compressedCount++
			if e.MimeType != MimeCompress {
				t.Fatalf("compressed entry mime=%d, want %d", e.MimeType, MimeCompress)
			}
			if e.OriginalSize == 0 {
				t.Fatal("compressed entry original_size must be > 0")
			}
		}
	}

	if candidateCount != 2 {
		t.Fatalf("compression candidates=%d, want 2", candidateCount)
	}
	if compressedCount != 1 {
		t.Fatalf("compressed callbacks=%d, want 1", compressedCount)
	}
}

func TestLargeWriteBufferRoundTrip(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("x"), 1024)
	inputs := []Input{{
		Path:     "a/b.txt",
		Open:     func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(payload)), nil },
		SizeHint: int64(len(payload)),
	}}

	out := filepath.Join(t.TempDir(), "out.pbo")
	if _, err := PackFile(context.Background(), out, inputs, PackOptions{WriterBufferSize: LargeWriteBuffer}); err != nil {
		t.Fatalf("pack: %v", err)
	}

	r, err := OpenWithOptions(out, ReaderOptions{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = r.Close() }()

	got, err := r.ReadEntry("a/b.txt")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch: got %d bytes", len(got))
	}
}

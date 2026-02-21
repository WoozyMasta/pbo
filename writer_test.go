// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

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

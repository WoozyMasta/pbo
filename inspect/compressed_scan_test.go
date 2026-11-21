// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/woozymasta/bimime"
	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

func TestSelectScanCompressedSmallUsesDecodedBytesForBothScans(t *testing.T) {
	comment := []byte("// compressed comment\n")
	commentPacked := compressFixture(t, comment)
	code := []byte("class Compressed { string value = \"ok\"; }\n")
	codePacked := compressFixture(t, code)
	reader := openTestReader(t, []archiveEntry{
		{
			name:         "blank.c",
			mime:         pbo.MimeCompress,
			originalSize: fixtureUint32(t, len(comment)),
			data:         commentPacked,
		},
		{
			name:         "script.paa",
			mime:         pbo.MimeCompress,
			originalSize: fixtureUint32(t, len(code)),
			data:         codePacked,
		},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:       true,
		ProbeContentType:    true,
		ScanCompressedSmall: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 1 ||
		matches[0].Raw.Path != "script.paa" ||
		!matches[0].Decoded ||
		!matches[0].TextLike {
		t.Fatalf("decoded matches = %#v", matches)
	}

	stats := selection.Statistics()
	if stats.CompressedCandidates != 2 ||
		stats.DecodedSmall != 2 ||
		stats.BlankOnly != 1 ||
		stats.Probed != 1 {
		t.Fatalf("compressed scan stats = %+v", stats)
	}
}

func TestSelectScanCompressedSmallAllowsRaisedPerEntryLimits(t *testing.T) {
	comment := bytes.Repeat([]byte("/* filler */\n"), 160)
	commentPacked := compressFixture(t, comment)
	reader := openTestReader(t, []archiveEntry{
		{
			name:         "large-comment.c",
			mime:         pbo.MimeCompress,
			originalSize: fixtureUint32(t, len(comment)),
			data:         commentPacked,
		},
		{
			name:         "large-packed.bin",
			mime:         pbo.MimeCompress,
			originalSize: 1,
			data:         bytes.Repeat([]byte{0xff}, 4097),
		},
	})

	defaults, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:       true,
		ScanCompressedSmall: true,
	})
	if err != nil {
		t.Fatalf("Select with defaults: %v", err)
	}
	if stats := defaults.Statistics(); stats.SkippedSizeBudget != 2 || len(defaults.Matches()) != 2 {
		t.Fatalf(
			"default compressed limits = %+v; matches=%d, want both entries retained as unknown",
			stats, len(defaults.Matches()),
		)
	}

	raised, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:          true,
		ScanCompressedSmall:    true,
		MaxCompressedScanBytes: 8192,
		MaxDecodedScanBytes:    4096,
		MaxBlankScanBytes:      4096,
	})
	if err != nil {
		t.Fatalf("Select with raised limits: %v", err)
	}
	if stats := raised.Statistics(); stats.SkippedSizeBudget != 0 ||
		stats.BlankOnly != 1 ||
		len(raised.Matches()) != 1 {
		t.Fatalf("raised compressed limits = %+v; matches=%#v", stats, raised.Matches())
	}
}

func TestSelectScanCompressedSmallHandlesZeroOutputAndDecodeFailure(t *testing.T) {
	validEmpty := []byte{0, 0, 0, 0}
	badChecksum := compressFixture(t, []byte("decoded payload"))
	badChecksum[len(badChecksum)-1] ^= 0xff
	falseCprs := []byte("class RawScript { int value = 1; }")
	reader := openTestReader(t, []archiveEntry{
		{
			name: "empty.bin",
			mime: pbo.MimeCompress,
			data: validEmpty,
		},
		{
			name:         "broken.bin",
			mime:         pbo.MimeCompress,
			originalSize: 15,
			data:         badChecksum,
		},
		{
			name:         "false-cprs.paa",
			mime:         pbo.MimeCompress,
			originalSize: fixtureUint32(t, len(falseCprs)),
			data:         falseCprs,
		},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:       true,
		ProbeContentType:    true,
		ScanCompressedSmall: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 2 ||
		matches[0].Raw.Path != "broken.bin" ||
		matches[1].Raw.Path != "false-cprs.paa" {
		t.Fatalf("decode-fallback matches = %#v", matches)
	}
	for _, match := range matches {
		if !match.RawFallback ||
			match.DecodeError == "" ||
			match.Decoded {
			t.Errorf("fallback diagnostic = %+v", match)
		}
	}
	if !matches[1].TextLike {
		t.Fatalf("false-Cprs source code was not recognized as text-like: %+v", matches[1])
	}

	stats := selection.Statistics()
	if stats.CompressedCandidates != 3 ||
		stats.DecodedSmall != 1 ||
		stats.DecodeFailed != 2 ||
		stats.RawFallback != 2 ||
		stats.BlankOnly != 1 {
		t.Fatalf("decode failure stats = %+v", stats)
	}
}

func TestSelectScanCompressedSmallHonorsBothBudgets(t *testing.T) {
	decoded := bytes.Repeat([]byte{'x'}, 1024)
	packed := compressFixture(t, decoded)
	reader := openTestReader(t, []archiveEntry{
		{
			name:         "at-limits.bin",
			mime:         pbo.MimeCompress,
			originalSize: 1024,
			data:         packed,
		},
		{
			name:         "packed-over.bin",
			mime:         pbo.MimeCompress,
			originalSize: 10,
			data:         bytes.Repeat([]byte{'x'}, 16),
		},
		{
			name:         "decoded-over.bin",
			mime:         pbo.MimeCompress,
			originalSize: 1025,
			data:         packed,
		},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		ScanCompressedSmall:    true,
		MaxCompressedScanBytes: fixtureUint32(t, len(packed)),
	})
	if err != nil {
		t.Fatalf("Select at limits: %v", err)
	}

	stats := selection.Statistics()
	if len(selection.Matches()) != 3 ||
		stats.DecodedSmall != 1 ||
		stats.DecodeFailed != 1 ||
		stats.SkippedSizeBudget != 1 {
		t.Fatalf("budget stats = %+v; matches=%d", stats, len(selection.Matches()))
	}

	selection, err = inspect.Select(context.Background(), reader, inspect.Options{
		ScanCompressedSmall:    true,
		MaxCompressedScanBytes: fixtureUint32(t, len(packed)-1),
	})
	if err != nil {
		t.Fatalf("Select below packed limit: %v", err)
	}
	if stats := selection.Statistics(); stats.DecodedSmall != 0 || stats.SkippedSizeBudget != 2 {
		t.Fatalf("strictly smaller packed budget stats = %+v", stats)
	}
}

func TestSelectScanCompressedSmallReportsTrailingDataAndHeuristicCompression(t *testing.T) {
	payload := []byte("MLOD")
	packed := compressFixture(t, payload)
	packed = append(packed, 0xde, 0xad)
	heuristic := []byte("false flag source")
	reader := openTestReader(t, []archiveEntry{
		{
			name:         "trailing.bin",
			mime:         pbo.MimeCompress,
			originalSize: fixtureUint32(t, len(payload)),
			data:         packed,
		},
		{
			name:         "heuristic.bin",
			originalSize: fixtureUint32(t, len(heuristic)+1),
			data:         heuristic,
		},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		ProbeContentType:    true,
		ScanCompressedSmall: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 2 ||
		!matches[0].Decoded ||
		matches[0].ProbeResult.ByContent != "bi.p3d.mlod" ||
		matches[0].ConsumedBytes >= matches[0].Raw.DataSize {
		t.Fatalf("trailing-data result = %#v", matches)
	}
	if !matches[1].RawFallback ||
		!matches[1].TextLike ||
		matches[1].Raw.MimeType == pbo.MimeCompress {
		t.Fatalf("heuristic compressed fallback = %#v", matches[1])
	}
	if stats := selection.Statistics(); stats.CompressedCandidates != 2 ||
		stats.ConsumedLessStored != 1 ||
		stats.RawFallback != 1 {
		t.Fatalf("trailing-data stats = %+v", stats)
	}
}

func TestSelectScanCompressedSmallAppliesContentTypeFiltersToDecodedBytes(t *testing.T) {
	image := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 152)...)
	reader := openTestReader(t, []archiveEntry{{
		name:         "resource.bin",
		mime:         pbo.MimeCompress,
		originalSize: fixtureUint32(t, len(image)),
		data:         compressFixture(t, image),
	}})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		ProbeContentType:     true,
		ScanCompressedSmall:  true,
		SkipDisallowedBinary: true,
		AllowedBinaryTypes:   []bimime.TypeID{"image.jpeg"},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	if len(selection.Matches()) != 0 || selection.Statistics().DisallowedBinary != 1 {
		t.Fatalf(
			"decoded disallowed content result: matches=%#v stats=%+v",
			selection.Matches(), selection.Statistics(),
		)
	}
}

func TestSelectScanCompressedSmallSkipsByDefaultAndAbortsReadErrors(t *testing.T) {
	packed := compressFixture(t, []byte("small payload"))
	readerAt, archiveSize := newCountingArchive(t, []archiveEntry{{
		name:         "small.bin",
		mime:         pbo.MimeCompress,
		originalSize: 13,
		data:         packed,
	}})
	reader, err := pbo.NewReaderFromReaderAt(readerAt, archiveSize)
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}

	t.Cleanup(func() { _ = reader.Close() })
	entry := reader.EntriesView()[0]
	readerAt.reset()
	selection, err := inspect.Select(
		context.Background(), reader, inspect.Options{ProbeContentType: true},
	)
	if err != nil {
		t.Fatalf("Select default compressed policy: %v", err)
	}

	if len(selection.Matches()) != 1 ||
		selection.Matches()[0].HasProbeResult ||
		readerAt.readCalls() != 0 {
		t.Fatalf(
			"default compressed result = %#v; payload reads=%d",
			selection.Matches(), readerAt.readCalls(),
		)
	}

	readerAt.reset()
	if _, err := inspect.Select(
		context.Background(), reader, inspect.Options{ScanCompressedSmall: true},
	); err != nil {
		t.Fatalf("Select bounded compressed scan: %v", err)
	}
	if got := readerAt.readSizes; len(got) != 1 || got[0] != len(packed) {
		t.Fatalf("compressed payload reads = %v, want exactly %d bytes", got, len(packed))
	}

	readerAt.reset()
	readerAt.failOffset = int64(entry.Offset)
	readerAt.failAt = true
	if _, err := inspect.Select(
		context.Background(), reader, inspect.Options{ScanCompressedSmall: true},
	); !errors.Is(err, errInjectedPayloadRead) {
		t.Fatalf("Select compressed read error = %v, want injected payload error", err)
	}
}

func compressFixture(t *testing.T, input []byte) []byte {
	t.Helper()
	packed, err := lzss.Compress(input, nil)
	if err != nil {
		t.Fatalf("lzss.Compress: %v", err)
	}

	return packed
}

// fixtureUint32 converts small synthetic fixture lengths to the PBO index type.
func fixtureUint32(t *testing.T, value int) uint32 {
	t.Helper()
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		t.Fatalf("fixture size %d does not fit uint32", value)
	}

	return uint32(value) // #nosec G115 -- range checked above.
}

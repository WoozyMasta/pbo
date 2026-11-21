// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

func TestSelectSkipBlankOnlyKeepsContentAndUnknown(t *testing.T) {
	entries := []archiveEntry{
		{name: "blank.c", data: bytes.Repeat([]byte{' '}, 1023)},
		{name: "boundary.c", data: append(bytes.Repeat([]byte{' '}, 1023), 'x')},
		{name: "oversized.c", data: bytes.Repeat([]byte{' '}, 1025)},
		{name: "renamed.paa", data: []byte("#include \"x.paa\"")},
		{name: "empty-cprs.bin", mime: pbo.MimeCompress, data: []byte{1, 2, 3, 4}},
		{name: "unclosed.c", data: []byte("/* unfinished")},
	}
	reader := openTestReader(t, entries)
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 5 ||
		matches[0].Raw.Path != "boundary.c" ||
		matches[1].Raw.Path != "oversized.c" ||
		matches[2].Raw.Path != "renamed.paa" ||
		matches[3].Raw.Path != "empty-cprs.bin" ||
		matches[4].Raw.Path != "unclosed.c" {
		t.Fatalf("matches = %#v", matches)
	}

	wantStats := inspect.Statistics{
		Visited:              6,
		Selected:             5,
		Excluded:             1,
		BlankOnly:            1,
		NotBlank:             2,
		NotScannedSize:       1,
		NotScannedCompressed: 1,
		Unknown:              3,
	}
	if got := selection.Statistics(); got != wantStats {
		t.Fatalf("Statistics = %#v, want %#v", got, wantStats)
	}
}

func TestSelectCombinedSizeBlankAndProbeKeepsCodeInPAA(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "scripts/comments.c", data: []byte("// this file is blank\n")},
		{name: "scripts/small.c", data: []byte("x")},
		{name: "scripts/hidden.paa", data: []byte("class Hidden { int value = 1; }\n")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		MinEstimatedSize: 12,
		SkipBlankOnly:    true,
		ProbeContentType: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 1 ||
		matches[0].Raw.Path != "scripts/hidden.paa" ||
		!matches[0].TextLike {
		t.Fatalf("combined selection = %#v", matches)
	}

	if stats := selection.Statistics(); stats.BlankOnly != 1 ||
		stats.Visited != 3 ||
		stats.Selected != 1 ||
		stats.Excluded != 2 {
		t.Fatalf("combined statistics = %+v", stats)
	}
}

func TestSelectBlankScanHonorsMetadataFiltersBeforePayloadRead(t *testing.T) {
	readerAt, archiveSize := newCountingArchive(t, []archiveEntry{
		{name: "keep/comment.c", data: []byte("// blank")},
		{name: "drop/content.c", data: []byte("class Keep {}")},
	})
	reader, err := pbo.NewReaderFromReaderAt(readerAt, archiveSize)
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}

	t.Cleanup(func() { _ = reader.Close() })
	filteredOffset := int64(reader.EntriesView()[1].Offset)
	readerAt.reset()

	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		PathPrefix:    "keep",
		SkipBlankOnly: true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	if len(selection.Matches()) != 0 || selection.Statistics().BlankOnly != 1 {
		t.Fatalf("selection = %#v; stats=%#v", selection.Matches(), selection.Statistics())
	}

	for _, offset := range readerAt.readOffsets {
		if offset >= filteredOffset {
			t.Fatalf("metadata-filtered payload at offset %d was read", offset)
		}
	}
}

func TestSelectBlankScanReadErrorAbortsSelection(t *testing.T) {
	readerAt, archiveSize := newCountingArchive(t, []archiveEntry{
		{name: "comment.c", data: []byte("// blank")},
		{name: "code.c", data: []byte("class Keep {}")},
	})
	reader, err := pbo.NewReaderFromReaderAt(readerAt, archiveSize)
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}

	t.Cleanup(func() { _ = reader.Close() })
	readerAt.reset()
	readerAt.failOffset = int64(reader.EntriesView()[0].Offset)
	readerAt.failAt = true

	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly: true,
	})
	if !errors.Is(err, errInjectedPayloadRead) {
		t.Fatalf("Select error = %v, want injected read error", err)
	}
	if selection.Entries() == nil || len(selection.Entries()) != 0 {
		t.Fatalf("partial selection = %#v, want empty", selection.Entries())
	}
}

func TestSelectBlankScanLimitCanBeOverridden(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{{name: "comments.c", data: []byte("//x")}})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:     true,
		MaxBlankScanBytes: 2,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	if got := selection.Statistics(); got.NotScannedSize != 1 ||
		got.Unknown != 1 ||
		got.Selected != 1 {
		t.Fatalf("Statistics = %#v", got)
	}
}

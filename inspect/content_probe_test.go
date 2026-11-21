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
	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

func TestSelectContentProbePreservesContentEvidenceAndText(t *testing.T) {
	textPayload := []byte("class Hidden { string value = \"ok\"; }\n")
	reader := openTestReader(t, []archiveEntry{
		{name: "renamed.txt", data: []byte("ODOL")},
		{name: "bare.unknownext", data: []byte("ODOL")},
		{name: "resource.c", data: append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 152)...)},
		{name: "wrong.png", data: append([]byte("ODOL"), bytes.Repeat([]byte{0}, 156)...)},
		{name: "script.paa", data: textPayload},
	})
	selection, err := inspect.Select(
		context.Background(), reader, inspect.Options{ProbeContentType: true},
	)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 5 {
		t.Fatalf("matches = %d, want 5", len(matches))
	}

	if matches[0].ProbeResult.ByContent != "bi.p3d.odol" ||
		matches[0].ProbeResult.Relation != bimime.RelationConflict ||
		!matches[0].ProbeResult.Has(bimime.FlagIncomplete) {
		t.Fatalf(
			"ODOL evidence = %+v, want retained content evidence with incomplete flag",
			matches[0].ProbeResult,
		)
	}

	if matches[1].ProbeResult.ByContent != "bi.p3d.odol" ||
		matches[1].ProbeResult.Relation != bimime.RelationContentOnly {
		t.Fatalf("content-only ODOL evidence = %+v", matches[1].ProbeResult)
	}

	if matches[2].ProbeResult.ByContent != "image.png" {
		t.Fatalf("renamed PNG content type = %q, want image.png", matches[2].ProbeResult.ByContent)
	}

	if matches[3].ProbeResult.Relation != bimime.RelationConflict {
		t.Fatalf("mismatched .png relation = %v, want conflict", matches[3].ProbeResult.Relation)
	}

	if !matches[4].TextLike || matches[4].ProbeResult.ByContent != "" {
		t.Fatalf("script-like .paa = %+v, want text-like unknown content", matches[4])
	}

	stats := selection.Statistics()
	if stats.Probed != 5 || stats.ByContent != 4 || stats.Incomplete != 3 || stats.Conflict != 3 {
		t.Fatalf("probe statistics = %+v", stats)
	}
}

func TestSelectBinaryPoliciesRequireCompleteEvidence(t *testing.T) {
	completeUnknown := bytes.Repeat([]byte{'A'}, 160)
	completeUnknown[0] = 0
	reader := openTestReader(t, []archiveEntry{
		{name: "unknown.bin", data: completeUnknown},
		{name: "short.bin", data: []byte{0}},
		{name: "known.bin", data: append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 152)...)},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		ProbeContentType:  true,
		SkipUnknownBinary: true,
	})
	if err != nil {
		t.Fatalf("Select unknown binary: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 2 ||
		matches[0].Raw.Path != "short.bin" ||
		matches[1].Raw.Path != "known.bin" {
		t.Fatalf("unknown-binary matches = %#v", matches)
	}
	if selection.Statistics().UnknownBinary != 1 {
		t.Fatalf("UnknownBinary = %d, want 1", selection.Statistics().UnknownBinary)
	}

	selection, err = inspect.Select(context.Background(), reader, inspect.Options{
		ProbeContentType:     true,
		SkipDisallowedBinary: true,
		AllowedBinaryTypes:   []bimime.TypeID{"image.jpeg"},
	})
	if err != nil {
		t.Fatalf("Select disallowed binary: %v", err)
	}

	if matches := selection.Matches(); len(matches) != 2 ||
		matches[0].Raw.Path != "unknown.bin" ||
		matches[1].Raw.Path != "short.bin" {
		t.Fatalf("disallowed-binary matches = %#v", matches)
	}
	if selection.Statistics().DisallowedBinary != 1 {
		t.Fatalf("DisallowedBinary = %d, want 1", selection.Statistics().DisallowedBinary)
	}
}

func TestSelectContentProbeRespectsPerEntryBoundAndReadErrors(t *testing.T) {
	readerAt, archiveSize := newCountingArchive(t, []archiveEntry{
		{name: "renamed.bin", data: []byte("ODOL plus trailing bytes")},
	})
	reader, err := pbo.NewReaderFromReaderAt(readerAt, archiveSize)
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}

	t.Cleanup(func() { _ = reader.Close() })
	entry := reader.EntriesView()[0]
	readerAt.reset()
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		ProbeContentType:     true,
		MaxContentProbeBytes: 4,
	})
	if err != nil {
		t.Fatalf("Select bounded probe: %v", err)
	}

	if matches := selection.Matches(); len(matches) != 1 ||
		matches[0].ProbeResult.ByContent != "bi.p3d.odol" ||
		!matches[0].ProbeResult.Has(bimime.FlagIncomplete) {
		t.Fatalf("short probe match = %#v", matches)
	}

	if got := readerAt.readOffsets; len(got) != 1 || got[0] != int64(entry.Offset) {
		t.Fatalf("payload read offsets = %v, want only %d", got, entry.Offset)
	}
	if got := readerAt.readSizes; len(got) != 1 || got[0] != 4 {
		t.Fatalf("payload read sizes = %v, want exactly 4 bytes", got)
	}

	readerAt.reset()
	if _, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipBlankOnly:    true,
		ProbeContentType: true,
	}); err != nil {
		t.Fatalf("Select combined scans: %v", err)
	}
	if got := readerAt.readSizes; len(got) != 1 || got[0] != len("ODOL plus trailing bytes") {
		t.Fatalf("combined scans payload reads = %v, want one blank-scan read", got)
	}

	readerAt.reset()
	readerAt.failOffset = int64(entry.Offset)
	readerAt.failAt = true
	if _, err := inspect.Select(
		context.Background(), reader, inspect.Options{ProbeContentType: true},
	); !errors.Is(err, errInjectedPayloadRead) {
		t.Fatalf("Select read error = %v, want injected payload error", err)
	}
}

func TestSelectValidatesBinaryPolicyOptions(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{{name: "data.bin", data: []byte("x")}})
	for _, opts := range []inspect.Options{
		{SkipUnknownBinary: true},
		{ProbeContentType: true, SkipDisallowedBinary: true},
		{ProbeContentType: true, AllowedBinaryTypes: []bimime.TypeID{"image.png"}},
		{ProbeContentType: true, SkipDisallowedBinary: true, AllowedBinaryTypes: []bimime.TypeID{"unknown.type"}},
		{ProbeContentType: true, SkipDisallowedBinary: true, AllowedBinaryTypes: []bimime.TypeID{"text.cfg"}},
		{ScanCompressedSmall: true, MaxCompressedScanBytes: inspect.HardMaxCompressedScanBytes + 1},
		{ScanCompressedSmall: true, MaxDecodedScanBytes: inspect.HardMaxDecodedScanBytes + 1},
		{SkipBlankOnly: true, MaxBlankScanBytes: inspect.HardMaxBlankScanBytes + 1},
	} {
		if _, err := inspect.Select(
			context.Background(), reader, opts,
		); !errors.Is(err, inspect.ErrInvalidOptions) {
			t.Errorf("Select(%+v) error = %v, want ErrInvalidOptions", opts, err)
		}
	}
}

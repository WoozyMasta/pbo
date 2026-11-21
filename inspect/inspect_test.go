// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

func TestSelectMetadataFiltersPreserveRawIdentityWithoutPayloadReads(t *testing.T) {
	readerAt, archiveSize := newCountingArchive(t, []archiveEntry{
		{name: `Scripts\Main.C`, data: []byte("first")},
		{name: `scripts\sub\main.c`, data: []byte("second longer")},
		{name: "scripts2/main.c", data: []byte("neighbor")},
		{name: "scripts/тест.c", data: []byte("unicode")},
	})
	reader, err := pbo.NewReaderFromReaderAt(readerAt, archiveSize)
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	readerAt.reset()

	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		PathPrefix:       `scripts`,
		MinEstimatedSize: 6,
		MaxEstimatedSize: 13,
		MinStoredSize:    6,
		MaxStoredSize:    13,
		ASCIIOnly:        true,
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if readerAt.readCalls() != 0 {
		t.Fatalf("Select performed %d payload ReaderAt reads", readerAt.readCalls())
	}

	matches := selection.Matches()
	if len(matches) != 1 || matches[0].SourceIndex != 1 || matches[0].Raw.Path != `scripts\sub\main.c` {
		t.Fatalf("matches = %#v, want source index 1 with raw path", matches)
	}
	if stats := selection.Statistics(); stats != (inspect.Statistics{Visited: 4, Selected: 1, Excluded: 3}) {
		t.Fatalf("Statistics = %#v", stats)
	}
	if got := selection.Entries()[0].Path; got != `scripts\sub\main.c` {
		t.Fatalf("Entries path = %q, want original path", got)
	}
}

func TestSelectSkipRulesKeepEmptyOriginalSizeCprsByDefault(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "empty.txt"},
		{name: "empty-cprs.bin", mime: pbo.MimeCompress, data: []byte{1, 2, 3, 4}},
		{name: "../escape.c", data: []byte("code")},
		{name: "keep.c", data: []byte("code")},
	})

	all, err := inspect.Select(context.Background(), reader, inspect.Options{})
	if err != nil {
		t.Fatalf("Select defaults: %v", err)
	}
	if len(all.Matches()) != 4 {
		t.Fatalf("default matches = %d, want 4", len(all.Matches()))
	}

	filtered, err := inspect.Select(context.Background(), reader, inspect.Options{
		SkipEmpty:        true,
		SkipInvalidPaths: true,
	})
	if err != nil {
		t.Fatalf("Select skip rules: %v", err)
	}
	matches := filtered.Matches()
	if len(matches) != 2 || matches[0].Raw.Path != "empty-cprs.bin" || matches[1].Raw.Path != "keep.c" {
		t.Fatalf("filtered matches = %#v, want empty-cprs.bin and keep.c", matches)
	}

	compressed, err := inspect.Select(context.Background(), reader, inspect.Options{SkipEmpty: true})
	if err != nil {
		t.Fatalf("Select with SkipEmpty: %v", err)
	}
	if len(compressed.Matches()) != 3 || compressed.Matches()[0].Raw.Path != "empty-cprs.bin" {
		t.Fatalf("SkipEmpty dropped zero OriginalSize Cprs: %#v", compressed.Matches())
	}
}

func TestSelectSizeBoundsAreInclusive(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "estimated-4", originalSize: 4, data: []byte("x")},
		{name: "estimated-5", originalSize: 5, data: []byte("x")},
		{name: "estimated-6", originalSize: 6, data: []byte("x")},
		{name: "stored-fallback-5", data: []byte("12345")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{
		MinEstimatedSize: 5,
		MaxEstimatedSize: 5,
	})
	if err != nil {
		t.Fatalf("Select estimated range: %v", err)
	}

	if matches := selection.Matches(); len(matches) != 2 ||
		matches[0].SourceIndex != 1 ||
		matches[1].SourceIndex != 3 {
		t.Fatalf("estimated size matches = %#v, want indexes 1 and 3", matches)
	}

	selection, err = inspect.Select(context.Background(), reader, inspect.Options{
		MinStoredSize: 5,
		MaxStoredSize: 5,
	})
	if err != nil {
		t.Fatalf("Select stored range: %v", err)
	}
	if matches := selection.Matches(); len(matches) != 1 || matches[0].SourceIndex != 3 {
		t.Fatalf("stored size matches = %#v, want index 3", matches)
	}
}

func TestSelectPrefixUsesRawNormalizedASCIIFoldedPath(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: `Scripts\main.c`, data: []byte("a")},
		{name: "scripts2/main.c", data: []byte("b")},
		{name: "É/main.c", data: []byte("c")},
		{name: "é/main.c", data: []byte("d")},
	})

	selection, err := inspect.Select(context.Background(), reader, inspect.Options{PathPrefix: "scripts"})
	if err != nil {
		t.Fatalf("Select scripts: %v", err)
	}
	if len(selection.Matches()) != 1 || selection.Matches()[0].SourceIndex != 0 {
		t.Fatalf("scripts selection = %#v", selection.Matches())
	}

	unicodeSelection, err := inspect.Select(context.Background(), reader, inspect.Options{PathPrefix: "É"})
	if err != nil {
		t.Fatalf("Select Unicode prefix: %v", err)
	}
	if len(unicodeSelection.Matches()) != 1 || unicodeSelection.Matches()[0].SourceIndex != 2 {
		t.Fatalf("Unicode prefix selection = %#v", unicodeSelection.Matches())
	}
}

func TestSelectPrefixNormalizesDotSegmentsAndWhitespace(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "./scripts/a.c", data: []byte("a")},
		{name: "/scripts/b.c", data: []byte("b")},
		{name: "scripts2/c.c", data: []byte("c")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{PathPrefix: " .\\scripts\\ "})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(selection.Matches()) != 2 || selection.Matches()[0].SourceIndex != 0 ||
		selection.Matches()[1].SourceIndex != 1 {
		t.Fatalf("normalized prefix matches = %#v", selection.Matches())
	}
}

func TestSelectASCIIOnlyUsesRawPathBytes(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "scripts/main.c", data: []byte("a")},
		{name: "scripts/тест.c", data: []byte("b")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{ASCIIOnly: true})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if len(selection.Matches()) != 1 || selection.Matches()[0].Raw.Path != "scripts/main.c" {
		t.Fatalf("ASCII-only matches = %#v", selection.Matches())
	}
}

func TestViewSanitizesSelectedSetAndPreservesRawIdentity(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "other/skip.txt", data: []byte("x")},
		{name: "data/CON.txt", data: []byte("reserved")},
		{name: "data/a:b.txt", data: []byte("first")},
		{name: "data/a?b.txt", data: []byte("second")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{PathPrefix: "DATA"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	view, err := inspect.View(selection, inspect.ViewOptions{FilesystemSafe: true})
	if err != nil {
		t.Fatalf("View: %v", err)
	}

	wantPaths := []string{"data/_CON.txt", "data/a_b.txt", "data/a_b~2.txt"}
	for index, want := range wantPaths {
		if view[index].DisplayPath != want {
			t.Errorf("view[%d].DisplayPath = %q, want %q", index, view[index].DisplayPath, want)
		}
		if view[index].Raw.Path != selection.Matches()[index].Raw.Path {
			t.Errorf("view[%d] changed raw path: %q", index, view[index].Raw.Path)
		}
		if view[index].ParentPath != "data" {
			t.Errorf("view[%d].ParentPath = %q, want data", index, view[index].ParentPath)
		}
	}
	if selection.Entries()[1].Path != "data/a:b.txt" {
		t.Fatal("View modified the selection's raw entries")
	}

	destination := filepath.Join(t.TempDir(), "selected")
	if err := reader.Extract(context.Background(), destination, pbo.ExtractOptions{
		Entries: selection.Entries(),
	}); err != nil {
		t.Fatalf("Extract selected entries: %v", err)
	}
	for _, displayPath := range wantPaths {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(displayPath))); err != nil {
			t.Errorf("Extract did not create view path %q: %v", displayPath, err)
		}
	}
}

func TestViewControlCharsRetainsOriginalPath(t *testing.T) {
	invalidUTF8 := string([]byte{'b', 'a', 'd', 0xff, '.', 'c'})
	reader := openTestReader(t, []archiveEntry{
		{name: "a\x1b[31m.txt", data: []byte("first")},
		{name: "scripts/\u200fname.c", data: []byte("second")},
		{name: "a\x01.txt", data: []byte("third")},
		{name: "a_.txt", data: []byte("fourth")},
		{name: invalidUTF8, data: []byte("fifth")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	view, err := inspect.View(selection, inspect.ViewOptions{ControlChars: true})
	if err != nil {
		t.Fatalf("View: %v", err)
	}

	want := []string{"a_[31m.txt", "scripts/_name.c", "a_.txt", "a_~2.txt", "bad_.c"}
	for index := range want {
		if view[index].DisplayPath != want[index] {
			t.Errorf("view[%d].DisplayPath = %q, want %q", index, view[index].DisplayPath, want[index])
		}
		if view[index].Raw.Path != selection.Matches()[index].Raw.Path {
			t.Errorf("view[%d] changed raw path", index)
		}
	}
}

func TestSelectDuplicateNamesKeepPhysicalIdentity(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{
		{name: "duplicate.txt", data: []byte("first")},
		{name: "duplicate.txt", data: []byte("second")},
	})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	matches := selection.Matches()
	if len(matches) != 2 || matches[0].SourceIndex != 0 || matches[1].SourceIndex != 1 {
		t.Fatalf("duplicate matches = %#v", matches)
	}

	for index, want := range []string{"first", "second"} {
		stream, err := reader.OpenEntryInfo(matches[index].Raw)
		if err != nil {
			t.Fatalf("OpenEntryInfo(%d): %v", index, err)
		}

		got, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatalf("read entry %d: %v", index, err)
		}
		if string(got) != want {
			t.Errorf("entry %d = %q, want %q", index, got, want)
		}
	}

	destination := filepath.Join(t.TempDir(), "selected")
	if err := reader.Extract(context.Background(), destination, pbo.ExtractOptions{
		Entries: []pbo.EntryInfo{matches[1].Raw},
	}); err != nil {
		t.Fatalf("Extract one duplicate: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destination, "duplicate.txt"))
	if err != nil {
		t.Fatalf("read extracted duplicate: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("extracted duplicate = %q, want second", got)
	}
}

func TestEmptySelectionIsSafeForExtract(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{{name: "keep.txt", data: []byte("data")}})
	selection, err := inspect.Select(context.Background(), reader, inspect.Options{PathPrefix: "missing"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}

	entries := selection.Entries()
	if entries == nil || len(entries) != 0 {
		t.Fatalf("empty selection entries = %#v, want non-nil empty slice", entries)
	}

	destination := filepath.Join(t.TempDir(), "not-created")
	if err := reader.Extract(context.Background(), destination, pbo.ExtractOptions{Entries: entries}); err != nil {
		t.Fatalf("Extract empty selection: %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination stat error = %v, want not-exist", err)
	}
}

func TestSelectValidatesOptionsAndContext(t *testing.T) {
	reader := openTestReader(t, []archiveEntry{{name: "file.txt", data: []byte("x")}})
	if _, err := inspect.Select(
		context.Background(), nil, inspect.Options{},
	); !errors.Is(err, pbo.ErrNilReader) {
		t.Fatalf("nil reader error = %v, want pbo.ErrNilReader", err)
	}

	var nilContext context.Context
	if _, err := inspect.Select(
		nilContext, reader, inspect.Options{},
	); !errors.Is(err, inspect.ErrNilContext) {
		t.Fatalf("nil context error = %v, want ErrNilContext", err)
	}

	if _, err := inspect.Select(context.Background(), reader, inspect.Options{
		MinEstimatedSize: 4,
		MaxEstimatedSize: 3,
	}); !errors.Is(err, inspect.ErrInvalidOptions) {
		t.Fatalf("invalid range error = %v, want ErrInvalidOptions", err)
	}

	if _, err := inspect.Select(context.Background(), reader, inspect.Options{
		MinStoredSize: 4,
		MaxStoredSize: 3,
	}); !errors.Is(err, inspect.ErrInvalidOptions) {
		t.Fatalf("invalid stored range error = %v, want ErrInvalidOptions", err)
	}

	if _, err := inspect.Select(context.Background(), reader, inspect.Options{
		PathPrefix: "../",
	}); !errors.Is(err, inspect.ErrInvalidOptions) {
		t.Fatalf("invalid path prefix error = %v, want ErrInvalidOptions", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspect.Select(ctx, reader, inspect.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Select error = %v, want context.Canceled", err)
	}
}

type archiveEntry struct {
	name         string
	mime         pbo.MimeType
	originalSize uint32
	data         []byte
}

// errInjectedPayloadRead is returned by tests that fail one payload access.
var errInjectedPayloadRead = errors.New("injected payload read failure")

// countingReaderAt records payload access performed by inspect tests.
type countingReaderAt struct {
	// reader is the wrapped archive source.
	reader io.ReaderAt
	// calls counts delegated ReadAt operations.
	calls int
	// readOffsets stores offsets passed to delegated ReadAt calls.
	readOffsets []int64
	// readSizes stores requested byte counts for delegated reads.
	readSizes []int
	// failOffset is the first offset that triggers the injected error.
	failOffset int64
	// failAt enables the injected read error.
	failAt bool
}

func (r *countingReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	r.calls++
	r.readOffsets = append(r.readOffsets, offset)
	r.readSizes = append(r.readSizes, len(dst))
	if r.failAt && offset >= r.failOffset {
		return 0, errInjectedPayloadRead
	}

	return r.reader.ReadAt(dst, offset)
}

// reset clears the accumulated read measurements.
func (r *countingReaderAt) reset() {
	r.calls = 0
	r.readOffsets = nil
	r.readSizes = nil
}

// readCalls returns the number of delegated read operations.
func (r *countingReaderAt) readCalls() int {
	return r.calls
}

func newCountingArchive(t *testing.T, entries []archiveEntry) (*countingReaderAt, int64) {
	t.Helper()
	data := buildArchive(t, entries)
	return &countingReaderAt{reader: bytes.NewReader(data)}, int64(len(data))
}

func openTestReader(t *testing.T, entries []archiveEntry) *pbo.Reader {
	t.Helper()
	data := buildArchive(t, entries)
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	return reader
}

func buildArchive(t *testing.T, entries []archiveEntry) []byte {
	t.Helper()
	const headerSize = 21
	buffer := bytes.NewBuffer(make([]byte, 0, headerSize+1+len(entries)*32))
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(pbo.MimeHeader))
	buffer.Write(header)
	buffer.WriteByte(0)

	for _, entry := range entries {
		buffer.WriteString(entry.name)
		buffer.WriteByte(0)
		fields := make([]byte, 20)
		binary.LittleEndian.PutUint32(fields[0:4], uint32(entry.mime))
		binary.LittleEndian.PutUint32(fields[4:8], entry.originalSize)
		//nolint:gosec // Test payload sizes are bounded fixtures.
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(entry.data)))
		buffer.Write(fields)
	}

	buffer.WriteByte(0)
	buffer.Write(make([]byte, 20))
	for _, entry := range entries {
		buffer.Write(entry.data)
	}

	return buffer.Bytes()
}

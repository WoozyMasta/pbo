// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"io"
	"testing"
)

func TestReaderEntryViewsKeepRawEntriesAndPayloadIdentity(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "a:b.txt", data: []byte("first")},
		{name: "a?b.txt", data: []byte("second")},
		{name: "small.txt", data: []byte("x")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer func() { _ = r.Close() }()

	raw := r.entries
	if len(raw) != 3 || raw[0].Path != "a:b.txt" || raw[1].Path != "a?b.txt" || raw[2].Path != "small.txt" {
		t.Fatalf("raw entries lost or changed: %#v", raw)
	}

	defaultEntries := r.Entries()
	if len(defaultEntries) != 3 || defaultEntries[0].Path != "a:b.txt" || defaultEntries[1].Path != "a?b.txt" {
		t.Fatalf("default entries = %#v, want raw entries", defaultEntries)
	}

	all, err := r.EntriesWithOptions(EntryViewOptions{})
	if err != nil {
		t.Fatalf("EntriesWithOptions raw: %v", err)
	}
	if len(all) != 3 || all[0].Path != "a:b.txt" || all[1].Path != "a?b.txt" {
		t.Fatalf("unfiltered view = %#v, want raw entries", all)
	}

	filtered, err := r.EntriesWithOptions(EntryViewOptions{
		MinOriginalSize: 2,
		SanitizeNames:   true,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptions sanitized: %v", err)
	}
	if len(filtered) != 2 || filtered[0].Path != "a_b.txt" || filtered[1].Path != "a_b~2.txt" {
		t.Fatalf("sanitized view = %#v", filtered)
	}

	for i, want := range []string{"first", "second"} {
		stream, err := r.OpenEntryInfo(filtered[i])
		if err != nil {
			t.Fatalf("OpenEntryInfo(%q): %v", filtered[i].Path, err)
		}
		got, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatalf("read OpenEntryInfo(%q): %v", filtered[i].Path, err)
		}
		if !bytes.Equal(got, []byte(want)) {
			t.Fatalf("OpenEntryInfo(%q) = %q, want %q", filtered[i].Path, got, want)
		}
	}
}

func TestReaderRawEntriesPreserveDuplicateAndInvalidUTF8Paths(t *testing.T) {
	t.Parallel()

	invalidUTF8 := string([]byte{'b', 'a', 'd', 0xff, '.', 'p', 'b', 'o'})
	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "duplicate.txt", data: []byte("first")},
		{name: "duplicate.txt", data: []byte("second")},
		{name: "control\x1bname.txt", data: []byte("third")},
		{name: invalidUTF8, data: []byte("fourth")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer func() { _ = r.Close() }()

	raw := r.entries
	if len(raw) != 4 {
		t.Fatalf("raw entry count = %d, want 4", len(raw))
	}
	if raw[0].Path != "duplicate.txt" || raw[1].Path != "duplicate.txt" ||
		raw[2].Path != "control\x1bname.txt" || raw[3].Path != invalidUTF8 {
		t.Fatalf("raw paths changed: %#v", raw)
	}

	view, err := r.EntriesWithOptions(EntryViewOptions{
		FilterJunk:           true,
		SanitizeControlChars: true,
		SanitizeNames:        true,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptions: %v", err)
	}
	if len(view) != 4 || view[0].Path == view[1].Path {
		t.Fatalf("sanitized duplicate paths should be deterministic and unique: %#v", view)
	}
}

func TestEntryView_CombinedSanitizationPreservesNamesAndProvenance(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "a\x1bb.txt", Offset: 10},
		{Path: "a_b.txt", Offset: 20},
		{Path: "a?b.txt", Offset: 30},
	}
	got, err := applyEntryViewOptions(entries, EntryViewOptions{
		SanitizeControlChars: true,
		SanitizeNames:        true,
	})
	if err != nil {
		t.Fatalf("applyEntryViewOptions: %v", err)
	}

	wantPaths := []string{"a_b.txt", "a_b~2.txt", "a_b~3.txt"}
	for i := range wantPaths {
		if got[i].Path != wantPaths[i] {
			t.Errorf("got[%d].Path=%q, want %q", i, got[i].Path, wantPaths[i])
		}
		if got[i].Offset != entries[i].Offset {
			t.Errorf("got[%d].Offset=%d, want %d", i, got[i].Offset, entries[i].Offset)
		}
	}
}

func TestArchiveLookupKeyFoldsASCIIOnly(t *testing.T) {
	t.Parallel()

	if archiveLookupKey(`Scripts\\Foo.C`) != archiveLookupKey("scripts/foo.c") {
		t.Fatal("ASCII path lookup should normalize separators and case")
	}
	if archiveLookupKey("É.txt") == archiveLookupKey("é.txt") {
		t.Fatal("non-ASCII path bytes must not be case-folded")
	}

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `Scripts\Foo.C`, data: []byte("payload")},
	})
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	got, err := r.ReadEntry("scripts/foo.c")
	if err != nil {
		t.Fatalf("ReadEntry normalized case: %v", err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Fatalf("ReadEntry = %q, want payload", got)
	}
}

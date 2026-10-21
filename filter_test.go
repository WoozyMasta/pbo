// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import "testing"

func TestEntriesWithOptions_SizeFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "small.txt", data: []byte("1234")},
		{name: "big.txt", data: []byte("1234567890abcd")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{MinOriginalSize: 12})
	if err != nil {
		t.Fatalf("EntriesWithOptions size filter: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "big.txt" {
		t.Fatalf("entries[0].Path=%q, want big.txt", entries[0].Path)
	}
}

func TestEntriesWithOptions_PrefixFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `data\a.txt`, data: []byte("A")},
		{name: `data\sub\b.txt`, data: []byte("B")},
		{name: `scripts\c.txt`, data: []byte("C")},
	})
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{PathPrefix: "data"})
	if err != nil {
		t.Fatalf("EntriesWithOptions: %v", err)
	}
	want := []string{`data\a.txt`, `data\sub\b.txt`}
	if len(entries) != len(want) {
		t.Fatalf("entry count=%d, want %d", len(entries), len(want))
	}
	for i := range want {
		if entries[i].Path != want[i] {
			t.Errorf("entries[%d].Path=%q, want %q", i, entries[i].Path, want[i])
		}
	}
}

func TestEntriesWithOptionsIndexed_SanitizedFilteredView(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `other\skip.txt`, data: []byte("0")},
		{name: `data\CON.txt`, data: []byte("1")},
		{name: `data\a:b.txt`, data: []byte("2")},
		{name: `data\a?b.txt`, data: []byte("3")},
		{name: `root.txt`, data: []byte("4")},
	})
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	view, err := r.EntriesWithOptionsIndexed(EntryViewOptions{
		PathPrefix:    "data",
		SanitizeNames: true,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptionsIndexed: %v", err)
	}

	wantPaths := []string{"data/_CON.txt", "data/a_b.txt", "data/a_b~2.txt"}
	wantIndices := []int{1, 2, 3}
	if len(view) != len(wantPaths) {
		t.Fatalf("len(view)=%d, want %d", len(view), len(wantPaths))
	}
	for i := range wantPaths {
		if view[i].Entry.Path != wantPaths[i] {
			t.Errorf("view[%d].Entry.Path=%q, want %q", i, view[i].Entry.Path, wantPaths[i])
		}
		if view[i].SourceIndex != wantIndices[i] {
			t.Errorf("view[%d].SourceIndex=%d, want %d", i, view[i].SourceIndex, wantIndices[i])
		}
		if view[i].ParentPath != "data" {
			t.Errorf("view[%d].ParentPath=%q, want data", i, view[i].ParentPath)
		}
	}
}

func TestEntriesWithOptionsIndexed_RootParentAndNilReader(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "root.txt", data: []byte("root")},
	})
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	view, err := r.EntriesWithOptionsIndexed(EntryViewOptions{})
	if err != nil {
		t.Fatalf("EntriesWithOptionsIndexed: %v", err)
	}
	if len(view) != 1 || view[0].SourceIndex != 0 || view[0].ParentPath != "" {
		t.Fatalf("unexpected root view: %#v", view)
	}
	if _, err := (*Reader)(nil).EntriesWithOptionsIndexed(EntryViewOptions{}); err != ErrNilReader {
		t.Fatalf("nil reader error=%v, want %v", err, ErrNilReader)
	}
}

func TestEntriesWithOptions_SizeFilterAndSanitize(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "CON.txt", data: []byte("1234")},
		{name: "big.txt", data: []byte("1234567890abcd")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("OpenWithOptions size filter: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{
		SanitizeNames:   true,
		MinOriginalSize: 12,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptions size filter: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "big.txt" {
		t.Fatalf("entries[0].Path=%q, want big.txt", entries[0].Path)
	}
}

func TestEntriesWithOptions_PrefixFilterBeforeSanitize(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `data\ a \COM2.c`, data: []byte("A")},
		{name: `scripts\COM2.c`, data: []byte("B")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{
		PathPrefix:    "data",
		SanitizeNames: true,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptions prefix filter: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "data/a/_COM2.c" {
		t.Fatalf("entries[0].Path=%q, want data/a/_COM2.c", entries[0].Path)
	}
}

func TestEntriesWithOptions_ASCIIOnlyFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "scripts/main.c", data: []byte("A")},
		{name: "scripts/тест.c", data: []byte("B")},
		{name: "config.cpp", data: []byte("C")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{FilterASCIIOnly: true})
	if err != nil {
		t.Fatalf("EntriesWithOptions ASCII filter: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries)=%d, want 2", len(entries))
	}

	if entries[0].Path != "scripts/main.c" {
		t.Fatalf("entries[0].Path=%q, want scripts/main.c", entries[0].Path)
	}

	if entries[1].Path != "config.cpp" {
		t.Fatalf("entries[1].Path=%q, want config.cpp", entries[1].Path)
	}
}

func TestEntriesWithOptions_SanitizePrefixFilter_ObfuscatedSpacesAndGUID(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `scripts\4_world\ nLhotvu0 \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`, data: []byte("A")},
		{name: `scripts\4_world\ other \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`, data: []byte("B")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries, err := r.EntriesWithOptions(EntryViewOptions{
		SanitizeNames: true,
		PathPrefix:    `scripts/4_world/nLhotvu0/.{22877a6d-37a1-461a-91b0-dbda5aaebc99}`,
	})
	if err != nil {
		t.Fatalf("EntriesWithOptions sanitize prefix filter: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "scripts/4_world/nLhotvu0/_{22877a6d-37a1-461a-91b0-dbda5aaebc99}/_COM2.c" {
		t.Fatalf("entries[0].Path=%q, want scripts/4_world/nLhotvu0/_{22877a6d-37a1-461a-91b0-dbda5aaebc99}/_COM2.c", entries[0].Path)
	}
}

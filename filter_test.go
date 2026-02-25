// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import "testing"

func TestFilterEntriesBySize(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "a.txt", DataSize: 4, OriginalSize: 4},
		{Path: "b.txt", DataSize: 5, OriginalSize: 12},
		{Path: "c.txt", DataSize: 12, OriginalSize: 0},
	}

	filtered := filterEntriesBySize(entries, 12, 5)
	if len(filtered) != 2 {
		t.Fatalf("len(filtered)=%d, want 2", len(filtered))
	}

	if filtered[0].Path != "b.txt" {
		t.Fatalf("filtered[0].Path=%q, want b.txt", filtered[0].Path)
	}

	if filtered[1].Path != "c.txt" {
		t.Fatalf("filtered[1].Path=%q, want c.txt", filtered[1].Path)
	}
}

func TestListEntriesWithOptions_SizeFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "small.txt", data: []byte("1234")},
		{name: "big.txt", data: []byte("1234567890abcd")},
	})

	entries, err := ListEntriesWithOptions(path, ReaderOptions{MinEntryOriginalSize: 12})
	if err != nil {
		t.Fatalf("ListEntriesWithOptions size filter: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "big.txt" {
		t.Fatalf("entries[0].Path=%q, want big.txt", entries[0].Path)
	}
}

func TestOpenWithOptions_SizeFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "CON.txt", data: []byte("1234")},
		{name: "big.txt", data: []byte("1234567890abcd")},
	})

	r, err := OpenWithOptions(path, ReaderOptions{
		SanitizeNames:        true,
		MinEntryOriginalSize: 12,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions size filter: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "big.txt" {
		t.Fatalf("entries[0].Path=%q, want big.txt", entries[0].Path)
	}
}

func TestFilterEntriesByPrefix(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "data/a.txt"},
		{Path: "data/sub/b.txt"},
		{Path: "scripts/c.txt"},
	}

	filtered := filterEntriesByPrefix(entries, "data")
	if len(filtered) != 2 {
		t.Fatalf("len(filtered)=%d, want 2", len(filtered))
	}

	if filtered[0].Path != "data/a.txt" {
		t.Fatalf("filtered[0].Path=%q, want data/a.txt", filtered[0].Path)
	}

	if filtered[1].Path != "data/sub/b.txt" {
		t.Fatalf("filtered[1].Path=%q, want data/sub/b.txt", filtered[1].Path)
	}
}

func TestFilterEntriesByASCIIOnly(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "scripts/main.c"},
		{Path: "scripts/тест.c"},
		{Path: "data/ábc.txt"},
		{Path: "config.cpp"},
	}

	filtered := filterEntriesByASCIIOnly(entries)
	if len(filtered) != 2 {
		t.Fatalf("len(filtered)=%d, want 2", len(filtered))
	}

	if filtered[0].Path != "scripts/main.c" {
		t.Fatalf("filtered[0].Path=%q, want scripts/main.c", filtered[0].Path)
	}

	if filtered[1].Path != "config.cpp" {
		t.Fatalf("filtered[1].Path=%q, want config.cpp", filtered[1].Path)
	}
}

func TestOpenWithOptions_PrefixFilterBeforeSanitize(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `data\ a \COM2.c`, data: []byte("A")},
		{name: `scripts\COM2.c`, data: []byte("B")},
	})

	r, err := OpenWithOptions(path, ReaderOptions{
		EntryPathPrefix: "data",
		SanitizeNames:   true,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions prefix filter: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "data/a/_COM2.c" {
		t.Fatalf("entries[0].Path=%q, want data/a/_COM2.c", entries[0].Path)
	}
}

func TestOpenWithOptions_ASCIIOnlyFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "scripts/main.c", data: []byte("A")},
		{name: "scripts/тест.c", data: []byte("B")},
		{name: "config.cpp", data: []byte("C")},
	})

	r, err := OpenWithOptions(path, ReaderOptions{FilterASCIIOnly: true})
	if err != nil {
		t.Fatalf("OpenWithOptions ASCII filter: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
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

func TestOpenWithOptions_SanitizePrefixFilter_ObfuscatedSpacesAndGUID(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: `scripts\4_world\ nLhotvu0 \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`, data: []byte("A")},
		{name: `scripts\4_world\ other \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`, data: []byte("B")},
	})

	r, err := OpenWithOptions(path, ReaderOptions{
		SanitizeNames:   true,
		EntryPathPrefix: `scripts/4_world/nLhotvu0/.{22877a6d-37a1-461a-91b0-dbda5aaebc99}`,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions sanitize prefix filter: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}

	if entries[0].Path != "scripts/4_world/nLhotvu0/_{22877a6d-37a1-461a-91b0-dbda5aaebc99}/_COM2.c" {
		t.Fatalf("entries[0].Path=%q, want scripts/4_world/nLhotvu0/_{22877a6d-37a1-461a-91b0-dbda5aaebc99}/_COM2.c", entries[0].Path)
	}
}

func TestFilterEntriesBySanitizedPrefix_EmptyPrefix(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: `scripts\4_world\ nLhotvu0 \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`},
		{Path: `scripts\4_world\ other \  .{22877a6d-37a1-461a-91b0-dbda5aaebc99}\COM2.c`},
	}

	filtered := filterEntriesBySanitizedPrefix(entries, "")
	if len(filtered) != len(entries) {
		t.Fatalf("len(filtered)=%d, want %d", len(filtered), len(entries))
	}
}

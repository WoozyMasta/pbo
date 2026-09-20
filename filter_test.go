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

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizePathSegment(t *testing.T) {
	t.Parallel()

	longName := strings.Repeat("a", 400)
	gotLong, err := sanitizePathSegment(longName)
	if err != nil {
		t.Fatalf("sanitizePathSegment(long): %v", err)
	}
	if len(gotLong) > maxSanitizedSegmentLen {
		t.Fatalf("len(long)=%d, want <= %d", len(gotLong), maxSanitizedSegmentLen)
	}
	if gotLong == longName {
		t.Fatal("long segment was not shortened")
	}

	testCases := []struct {
		in   string
		want string
	}{
		{in: "CON.txt", want: "_CON.txt"},
		{in: "a:b?.txt", want: "a_b_.txt"},
		{in: "name. ", want: "name"},
		{in: "AUX:", want: "_AUX_"},
		{in: "CLOCK$.cfg", want: "_CLOCK$.cfg"},
		{in: "KBD$.txt", want: "_KBD$.txt"},
		{in: "POINTER$.txt", want: "_POINTER$.txt"},
		{in: "$ADDSTOR", want: "_$ADDSTOR"},
		{in: "82164A:", want: "_82164A_"},
	}

	for _, tc := range testCases {
		got, err := sanitizePathSegment(tc.in)
		if err != nil {
			t.Fatalf("sanitizePathSegment(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("sanitizePathSegment(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsReservedDeviceName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		want bool
	}{
		{name: "con", want: true},
		{name: "con.txt", want: true},
		{name: "AUX:", want: true},
		{name: "CLOCK$", want: true},
		{name: "pointer$.txt", want: true},
		{name: "normal.txt", want: false},
		{name: "_con.txt", want: false},
	}

	for _, tc := range testCases {
		got := isReservedDeviceName(tc.name)
		if got != tc.want {
			t.Fatalf("isReservedDeviceName(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSanitizeEntryInfoPathsCollision(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "a:b.txt"},
		{Path: "a?b.txt"},
	}

	got, err := sanitizeEntryInfoPaths(entries)
	if err != nil {
		t.Fatalf("sanitizeEntryInfoPaths: %v", err)
	}
	if got[0].Path != "a_b.txt" {
		t.Fatalf("got[0]=%q, want a_b.txt", got[0].Path)
	}
	if got[1].Path != "a_b~2.txt" {
		t.Fatalf("got[1]=%q, want a_b~2.txt", got[1].Path)
	}
}

func TestListEntriesWithOptionsSanitizeNames(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "CON.txt", data: []byte("a")},
		{name: "a:b.txt", data: []byte("b")},
		{name: "a?b.txt", data: []byte("c")},
	})

	rawEntries, err := ListEntries(path)
	if err != nil {
		t.Fatalf("ListEntries raw: %v", err)
	}
	if rawEntries[0].Path != "CON.txt" || rawEntries[1].Path != "a:b.txt" || rawEntries[2].Path != "a?b.txt" {
		t.Fatalf("unexpected raw paths: %#v", rawEntries)
	}

	sanitized, err := ListEntriesWithOptions(path, ReaderOptions{SanitizeNames: true})
	if err != nil {
		t.Fatalf("ListEntriesWithOptions sanitize: %v", err)
	}
	if sanitized[0].Path != "_CON.txt" || sanitized[1].Path != "a_b.txt" || sanitized[2].Path != "a_b~2.txt" {
		t.Fatalf("unexpected sanitized paths: %#v", sanitized)
	}
}

func TestExtractSanitizeNames(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "CON.txt", data: []byte("hello")},
		{name: "a:b.txt", data: []byte("world")},
		{name: "a?b.txt", data: []byte("x")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	outDir := t.TempDir()
	if err := r.Extract(context.Background(), outDir, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatalf("Extract sanitize: %v", err)
	}

	cases := []struct {
		path string
		want []byte
	}{
		{path: "_CON.txt", want: []byte("hello")},
		{path: "a_b.txt", want: []byte("world")},
		{path: "a_b~2.txt", want: []byte("x")},
	}

	for _, tc := range cases {
		got, err := os.ReadFile(filepath.Join(outDir, tc.path))
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s=%q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExtractDefaultSanitizeNames(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "a:b.txt", data: []byte("world")},
		{name: "a?b.txt", data: []byte("x")},
	})

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	outDir := t.TempDir()
	if err := r.Extract(context.Background(), outDir, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatalf("Extract default sanitize: %v", err)
	}

	cases := []struct {
		path string
		want []byte
	}{
		{path: "a_b.txt", want: []byte("world")},
		{path: "a_b~2.txt", want: []byte("x")},
	}

	for _, tc := range cases {
		got, err := os.ReadFile(filepath.Join(outDir, tc.path))
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("%s=%q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestExtractOptionsRawNamesFlag(t *testing.T) {
	t.Parallel()

	opts := ExtractOptions{}
	if opts.RawNames {
		t.Fatal("default ExtractOptions must keep sanitization enabled (RawNames=false)")
	}

	opts = ExtractOptions{RawNames: true}
	if !opts.RawNames {
		t.Fatal("RawNames=true must disable sanitization")
	}
}

type manualEntry struct {
	data []byte
	name string
}

// createManualPBOWithNamedEntries writes a minimal uncompressed PBO with entries in provided order.
func createManualPBOWithNamedEntries(t *testing.T, entries []manualEntry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "manual-multi.pbo")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create PBO: %v", err)
	}

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
	if _, err := f.Write(header); err != nil {
		_ = f.Close()
		t.Fatalf("write header: %v", err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		_ = f.Close()
		t.Fatalf("write header terminator: %v", err)
	}

	for _, e := range entries {
		if _, err := io.WriteString(f, e.name); err != nil {
			_ = f.Close()
			t.Fatalf("write name: %v", err)
		}
		if _, err := f.Write([]byte{0}); err != nil {
			_ = f.Close()
			t.Fatalf("write name terminator: %v", err)
		}

		fields := make([]byte, 20)
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(e.data)))
		if _, err := f.Write(fields); err != nil {
			_ = f.Close()
			t.Fatalf("write fields: %v", err)
		}
	}

	if _, err := f.Write([]byte{0}); err != nil {
		_ = f.Close()
		t.Fatalf("write entries terminator: %v", err)
	}
	if _, err := f.Write(make([]byte, 20)); err != nil {
		_ = f.Close()
		t.Fatalf("write entries tail: %v", err)
	}

	for _, e := range entries {
		if _, err := f.Write(e.data); err != nil {
			_ = f.Close()
			t.Fatalf("write payload: %v", err)
		}
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close PBO: %v", err)
	}

	return path
}

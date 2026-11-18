// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// createManualPBO writes a minimal PBO with one entry "a.txt" and the given payload; returns the path.
func createManualPBO(t *testing.T, payload []byte) string {
	t.Helper()
	return createManualPBOWithEntryPath(t, "a.txt", payload)
}

// createManualPBOWithEntryPath writes a minimal PBO with one custom entry path.
func createManualPBOWithEntryPath(t *testing.T, entryPath string, payload []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.pbo")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
	if _, err := f.Write(header); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after header write error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after header terminator error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(entryPath + "\x00")); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after entry name error: %v", closeErr)
		}
		t.Fatal(err)
	}

	entryBuf := make([]byte, 20)
	binary.LittleEndian.PutUint32(entryBuf[16:20], mustUint32ForTest(t, int64(len(payload))))
	if _, err := f.Write(entryBuf); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after entry fields error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after entry terminator error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 20)); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after sentinel error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after payload write error: %v", closeErr)
		}
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		if closeErr := f.Close(); closeErr != nil {
			t.Errorf("close after sync error: %v", closeErr)
		}
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestOpen_ManualPBO verifies the reader parses a hand-built minimal PBO.
func TestOpen_ManualPBO(t *testing.T) {
	path := createManualPBO(t, []byte("hello"))
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Path != "a.txt" || entries[0].DataSize != 5 {
		t.Errorf("entry: path=%q dataSize=%d", entries[0].Path, entries[0].DataSize)
	}

	data, err := r.ReadEntry("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("data: got %q", data)
	}
}

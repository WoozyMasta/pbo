// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/woozymasta/lzss"
)

// decodeFixtureEntry describes one hand-built PBO entry for decoder tests.
type decodeFixtureEntry struct {
	name         string   // Archive path stored in the index.
	data         []byte   // Exact packed bytes written after the index.
	originalSize uint32   // Decoded size advertised by the entry.
	mimeType     MimeType // Storage marker advertised by the entry.
}

// TestExtractChecksumFailureDoesNotExposeDecodedOutput verifies checksum failures do not replace output files.
func TestExtractChecksumFailureDoesNotExposeDecodedOutput(t *testing.T) {
	t.Parallel()

	decodedPayload := bytes.Repeat([]byte("compressed payload "), 2048)
	packedPayload, err := lzss.Compress(decodedPayload, nil)
	if err != nil {
		t.Fatalf("compress fixture: %v", err)
	}
	packedPayload[len(packedPayload)-1] ^= 0x80

	pboPath := createDecodeFixturePBO(t, []decodeFixtureEntry{
		{
			name:         "bad.bin",
			data:         packedPayload,
			originalSize: mustUint32ForTest(t, int64(len(decodedPayload))),
			mimeType:     MimeCompress,
		},
		{
			name: "good.txt",
			data: []byte("valid"),
		},
	})
	reader, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = reader.Close() }()

	entries := reader.Entries()
	badEntry := entries[0]

	var raw bytes.Buffer
	rawWritten, err := reader.CopyPackedEntryInfoTo(badEntry, &raw)
	if err != nil {
		t.Fatalf("CopyPackedEntryInfoTo: %v", err)
	}
	if rawWritten != int64(len(packedPayload)) || !bytes.Equal(raw.Bytes(), packedPayload) {
		t.Fatalf("raw payload differs: written=%d bytes=%d", rawWritten, raw.Len())
	}

	if _, err := reader.ReadEntry("bad.bin"); !errors.Is(err, ErrEntryDecompression) {
		t.Fatalf("ReadEntry error = %v, want ErrEntryDecompression", err)
	}
	stream, err := reader.OpenEntryInfo(badEntry)
	if err != nil {
		t.Fatalf("OpenEntryInfo: %v", err)
	}

	streamData, streamErr := io.ReadAll(stream)
	closeErr := stream.Close()
	if !errors.Is(streamErr, ErrEntryDecompression) {
		t.Fatalf("OpenEntryInfo error = %v, want ErrEntryDecompression", streamErr)
	}
	if closeErr != nil {
		t.Fatalf("OpenEntryInfo close: %v", closeErr)
	}
	if !bytes.Equal(streamData, decodedPayload) {
		t.Fatalf("stream yielded %d bytes before checksum error, want %d", len(streamData), len(decodedPayload))
	}

	var copied bytes.Buffer
	copiedBytes, err := reader.CopyEntryInfoTo(badEntry, &copied, nil)
	if !errors.Is(err, ErrEntryDecompression) {
		t.Fatalf("CopyEntryInfoTo error = %v, want ErrEntryDecompression", err)
	}
	if copiedBytes != int64(len(decodedPayload)) {
		t.Fatalf("CopyEntryInfoTo reported %d output bytes, want %d", copiedBytes, len(decodedPayload))
	}
	if !bytes.Equal(copied.Bytes(), decodedPayload) {
		t.Fatalf("copy yielded %d bytes before checksum error, want %d", copied.Len(), len(decodedPayload))
	}

	failFastDir := filepath.Join(t.TempDir(), "fail-fast")
	err = reader.Extract(context.Background(), failFastDir, ExtractOptions{MaxWorkers: 1})
	if err == nil {
		t.Fatal("fail-fast Extract accepted a bad checksum")
	}
	if _, err := os.Stat(filepath.Join(failFastDir, "bad.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed output exists after fail-fast extraction: %v", err)
	}

	continueDir := filepath.Join(t.TempDir(), "continue")
	if err := os.MkdirAll(continueDir, 0o750); err != nil {
		t.Fatal(err)
	}
	oldData := []byte("previous output")
	if err := os.WriteFile(filepath.Join(continueDir, "bad.bin"), oldData, 0o600); err != nil {
		t.Fatal(err)
	}

	err = reader.Extract(context.Background(), continueDir, ExtractOptions{
		MaxWorkers:      1,
		ContinueOnError: true,
	})
	if err == nil {
		t.Fatal("ContinueOnError extraction accepted a bad checksum")
	}

	gotBad, err := os.ReadFile(filepath.Join(continueDir, "bad.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBad, oldData) {
		t.Fatalf("failed entry replaced existing output with %d bytes", len(gotBad))
	}

	gotGood, err := os.ReadFile(filepath.Join(continueDir, "good.txt"))
	if err != nil {
		t.Fatalf("valid sibling was not extracted: %v", err)
	}
	if string(gotGood) != "valid" {
		t.Fatalf("valid sibling = %q, want %q", gotGood, "valid")
	}

	outputFiles, err := os.ReadDir(continueDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(outputFiles) != 2 {
		t.Fatalf("output directory contains %d files, want only the two entries", len(outputFiles))
	}
}

// TestExtractSmallChecksumFailureDoesNotCreateOutput verifies buffered decode errors precede file creation.
func TestExtractSmallChecksumFailureDoesNotCreateOutput(t *testing.T) {
	t.Parallel()

	decodedPayload := bytes.Repeat([]byte("small compressed payload"), 8)
	packedPayload, err := lzss.Compress(decodedPayload, nil)
	if err != nil {
		t.Fatalf("compress fixture: %v", err)
	}

	packedPayload[len(packedPayload)-1] ^= 0x80
	pboPath := createDecodeFixturePBO(t, []decodeFixtureEntry{{
		name:         "bad-small.bin",
		data:         packedPayload,
		originalSize: mustUint32ForTest(t, int64(len(decodedPayload))),
		mimeType:     MimeCompress,
	}})
	reader, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = reader.Close() }()

	outputDir := t.TempDir()
	err = reader.Extract(context.Background(), outputDir, ExtractOptions{MaxWorkers: 1})
	if !errors.Is(err, ErrEntryDecompression) {
		t.Fatalf("Extract error = %v, want ErrEntryDecompression", err)
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("output directory contains %d files after checksum failure, want 0", len(files))
	}
}

// TestExtractStagedCompressedCreateOnly preserves create-only semantics for staged output.
func TestExtractStagedCompressedCreateOnly(t *testing.T) {
	t.Parallel()

	decodedPayload := bytes.Repeat([]byte("staged compressed payload"), 2048)
	packedPayload, err := lzss.Compress(decodedPayload, nil)
	if err != nil {
		t.Fatalf("compress fixture: %v", err)
	}

	pboPath := createDecodeFixturePBO(t, []decodeFixtureEntry{{
		name:         "compressed.bin",
		data:         packedPayload,
		originalSize: mustUint32ForTest(t, int64(len(decodedPayload))),
		mimeType:     MimeCompress,
	}})
	reader, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = reader.Close() }()

	outputDir := t.TempDir()
	opts := ExtractOptions{MaxWorkers: 1, FileMode: ExtractFileModeCreateOnly}
	if err := reader.Extract(context.Background(), outputDir, opts); err != nil {
		t.Fatalf("first Extract: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outputDir, "compressed.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, decodedPayload) {
		t.Fatalf("extracted payload differs: got %d bytes, want %d", len(got), len(decodedPayload))
	}
	if err := reader.Extract(context.Background(), outputDir, opts); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second Extract error = %v, want os.ErrExist", err)
	}

	invalidOutputDir := t.TempDir()
	err = reader.Extract(context.Background(), invalidOutputDir, ExtractOptions{
		MaxWorkers: 1,
		FileMode:   "invalid",
	})
	if err == nil {
		t.Fatal("Extract accepted an unknown file mode")
	}

	files, err := os.ReadDir(invalidOutputDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("invalid file mode left %d output files, want 0", len(files))
	}
}

// createDecodeFixturePBO writes a minimal PBO with caller-selected entry metadata.
func createDecodeFixturePBO(t *testing.T, entries []decodeFixtureEntry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "decode-fixture.pbo")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
	if _, err := file.Write(header); err != nil {
		_ = file.Close()
		t.Fatalf("write header: %v", err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		t.Fatalf("write property terminator: %v", err)
	}

	for _, entry := range entries {
		if _, err := io.WriteString(file, entry.name); err != nil {
			_ = file.Close()
			t.Fatalf("write entry name: %v", err)
		}
		if _, err := file.Write([]byte{0}); err != nil {
			_ = file.Close()
			t.Fatalf("write entry name terminator: %v", err)
		}

		var fields [20]byte
		binary.LittleEndian.PutUint32(fields[0:4], uint32(entry.mimeType))
		binary.LittleEndian.PutUint32(fields[4:8], entry.originalSize)
		binary.LittleEndian.PutUint32(fields[16:20], mustUint32ForTest(t, int64(len(entry.data))))
		if _, err := file.Write(fields[:]); err != nil {
			_ = file.Close()
			t.Fatalf("write entry fields: %v", err)
		}
	}

	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		t.Fatalf("write entry terminator: %v", err)
	}
	if _, err := file.Write(make([]byte, 20)); err != nil {
		_ = file.Close()
		t.Fatalf("write trailing fields: %v", err)
	}

	for _, entry := range entries {
		if _, err := file.Write(entry.data); err != nil {
			_ = file.Close()
			t.Fatalf("write entry payload: %v", err)
		}
	}

	if err := file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	return path
}

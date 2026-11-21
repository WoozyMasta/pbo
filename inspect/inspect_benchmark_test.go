// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/woozymasta/bimime"
	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

// inspectBenchEntryCount is the large-index benchmark fixture size.
const inspectBenchEntryCount = 52536

// inspectBenchSink prevents benchmark results from being optimized away.
var inspectBenchSink int

func BenchmarkInspectSelectQueryAndViewLargeIndex(b *testing.B) {
	archive := buildInspectBenchArchive()
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	opts := inspect.Options{PathPrefix: inspectBenchPath(0)}
	b.ReportAllocs()
	for b.Loop() {
		selection, err := inspect.Select(context.Background(), reader, opts)
		if err != nil {
			b.Fatal(err)
		}

		view, err := inspect.View(selection, inspect.ViewOptions{FilesystemSafe: true})
		if err != nil {
			b.Fatal(err)
		}

		inspectBenchSink = len(view)
	}
}

func BenchmarkInspectSkipBlankOnlyHundredThousand(b *testing.B) {
	payload := []byte("// generated comment\n")
	archive := buildInspectArchive(100000, payload)
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	b.ReportAllocs()
	var lastStats inspect.Statistics
	for b.Loop() {
		selection, err := inspect.Select(context.Background(), reader, inspect.Options{SkipBlankOnly: true})
		if err != nil {
			b.Fatal(err)
		}

		lastStats = selection.Statistics()
		inspectBenchSink = lastStats.BlankOnly
	}

	b.SetBytes(int64(100000 * len(payload)))
	b.ReportMetric(100000, "entries/op")
	b.ReportMetric(float64(100000*len(payload)), "readbytes/op")
	b.ReportMetric(float64(lastStats.BlankOnly), "blank-only/op")
	b.ReportMetric(float64(lastStats.Selected), "selected/op")
}

func BenchmarkInspectMetadataOnlyHundredThousand(b *testing.B) {
	archive := buildInspectArchive(100000, nil)
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	b.ReportAllocs()
	var lastStats inspect.Statistics
	for b.Loop() {
		selection, err := inspect.Select(context.Background(), reader, inspect.Options{})
		if err != nil {
			b.Fatal(err)
		}
		lastStats = selection.Statistics()
		inspectBenchSink = lastStats.Selected
	}

	b.ReportMetric(float64(100000), "entries/op")
	b.ReportMetric(0, "readbytes/op")
	b.ReportMetric(float64(lastStats.Selected), "selected/op")
	b.ReportMetric(float64(lastStats.Excluded), "excluded/op")
}

func BenchmarkInspectProbeMagicHundredThousand(b *testing.B) {
	magic := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 152)...)
	archive := buildInspectArchive(100000, magic)
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	b.ReportAllocs()
	b.SetBytes(100000 * int64(len(magic)))
	b.ReportMetric(100000, "entries/op")
	probeBytes := bimime.RequiredPrefix(inspectBenchPath(0), bimime.ProfileThorough)
	var lastStats inspect.Statistics
	for b.Loop() {
		selection, err := inspect.Select(context.Background(), reader, inspect.Options{ProbeContentType: true})
		if err != nil {
			b.Fatal(err)
		}
		lastStats = selection.Statistics()
		inspectBenchSink = lastStats.ByContent
	}

	b.ReportMetric(float64(100000*probeBytes), "readbytes/op")
	b.ReportMetric(float64(lastStats.ByContent), "by-content/op")
	b.ReportMetric(float64(lastStats.Incomplete), "incomplete/op")
}

func BenchmarkInspectScanCompressedSmallHundredThousand(b *testing.B) {
	decoded := []byte("// generated compressed comment\n")
	packed, err := lzss.Compress(decoded, nil)
	if err != nil {
		b.Fatal(err)
	}

	archive := buildCompressedInspectArchive(100000, packed, len(decoded))
	reader, err := pbo.NewReaderFromReaderAt(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = reader.Close() }()

	b.ReportAllocs()
	b.ReportMetric(float64(100000*len(packed)), "packed-B/op")
	b.ReportMetric(float64(100000*len(decoded)), "decoded-B/op")
	b.ReportMetric(100000, "entries/op")
	var lastStats inspect.Statistics
	for b.Loop() {
		selection, err := inspect.Select(context.Background(), reader, inspect.Options{
			SkipBlankOnly:       true,
			ScanCompressedSmall: true,
		})
		if err != nil {
			b.Fatal(err)
		}
		lastStats = selection.Statistics()
		inspectBenchSink = lastStats.DecodedSmall
	}
	b.ReportMetric(float64(100000*len(packed)), "readbytes/op")
	b.ReportMetric(float64(100000*len(decoded)), "decodedbytes/op")
	b.ReportMetric(float64(100000), "entries/op")
	b.ReportMetric(float64(lastStats.DecodedSmall), "decoded-small/op")
	b.ReportMetric(float64(lastStats.BlankOnly), "blank-only/op")
}

// buildInspectBenchArchive creates the standard large-index benchmark archive.
func buildInspectBenchArchive() []byte {
	return buildInspectArchive(inspectBenchEntryCount, bytes.Repeat([]byte("x"), 96))
}

// buildInspectArchive creates an archive with repeated uncompressed payloads.
func buildInspectArchive(entryCount int, payload []byte) []byte {
	var archive bytes.Buffer
	header := make([]byte, 21)
	binary.LittleEndian.PutUint32(header[1:5], uint32(pbo.MimeHeader))
	archive.Write(header)
	archive.WriteByte(0)

	for index := range entryCount {
		archive.WriteString(inspectBenchPath(index))
		archive.WriteByte(0)
		fields := make([]byte, 20)
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(payload))) //nolint:gosec // Benchmark payloads are small fixed fixtures.
		archive.Write(fields)
	}
	archive.WriteByte(0)
	archive.Write(make([]byte, 20))
	for range entryCount {
		archive.Write(payload)
	}

	return archive.Bytes()
}

// buildCompressedInspectArchive creates an archive with repeated Cprs entries.
func buildCompressedInspectArchive(entryCount int, packed []byte, decodedSize int) []byte {
	var archive bytes.Buffer
	header := make([]byte, 21)
	binary.LittleEndian.PutUint32(header[1:5], uint32(pbo.MimeHeader))
	archive.Write(header)
	archive.WriteByte(0)
	for index := range entryCount {
		archive.WriteString(inspectBenchPath(index))
		archive.WriteByte(0)
		fields := make([]byte, 20)
		binary.LittleEndian.PutUint32(fields[0:4], uint32(pbo.MimeCompress))
		binary.LittleEndian.PutUint32(fields[4:8], uint32(decodedSize))   //nolint:gosec // Benchmark payload is a fixed small fixture.
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(packed))) //nolint:gosec // Benchmark payload is a fixed small fixture.
		archive.Write(fields)
	}
	archive.WriteByte(0)
	archive.Write(make([]byte, 20))
	for range entryCount {
		archive.Write(packed)
	}

	return archive.Bytes()
}

// inspectBenchPath returns a stable synthetic path for one benchmark record.
func inspectBenchPath(index int) string {
	return fmt.Sprintf("data/dir%03d/file%05d.c", index%100, index)
}

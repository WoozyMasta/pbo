package pbo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_InvalidHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pbo")
	if err := os.WriteFile(path, []byte("not a pbo header\x00\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for invalid header")
	}
	if !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("expected ErrInvalidHeader, got %v", err)
	}
}

func TestReaderLimits_EntryNameLength(t *testing.T) {
	name := bytes.Repeat([]byte("n"), maxNameLen+1)
	raw := makeReaderLimitFixture(nil, [][]byte{name})

	_, err := NewReaderFromReaderAt(bytes.NewReader(raw), int64(len(raw)))
	if !errors.Is(err, ErrFileNameTooLong) {
		t.Fatalf("expected ErrFileNameTooLong for default limit, got %v", err)
	}

	r, err := NewReaderFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxEntryNameBytes: len(name)},
	})
	if err != nil {
		t.Fatalf("open with raised name limit: %v", err)
	}
	defer func() { _ = r.Close() }()
	if got := r.EntriesView()[0].Path; len(got) != len(name) {
		t.Fatalf("entry name length=%d, want %d", len(got), len(name))
	}
}

func TestReaderLimits_LargeUnterminatedEntryNameStopsEarly(t *testing.T) {
	const sourceSize = int64(8 << 20)
	header := make([]byte, headerSize+1)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
	ra := &syntheticReaderAt{prefix: header, size: sourceSize, fill: 'n'}

	_, err := NewReaderFromReaderAt(ra, sourceSize)
	if !errors.Is(err, ErrFileNameTooLong) {
		t.Fatalf("expected ErrFileNameTooLong, got %v", err)
	}
	if read := ra.maxReadEnd - int64(len(header)); read > readerEntryBufferSize {
		t.Fatalf("scanner read %d bytes for an overlong name, buffer limit is %d", read, readerEntryBufferSize)
	}

	spillReader := &syntheticReaderAt{prefix: header, size: sourceSize, fill: 'n'}
	index := io.NewSectionReader(spillReader, int64(len(header)), sourceSize-int64(len(header)))
	buffered := bufio.NewReaderSize(index, readerEntryBufferSize)
	var spill []byte
	_, _, err = readNullTerminatedBuffered(buffered, &spill, maxNameLen)
	if !errors.Is(err, ErrFileNameTooLong) {
		t.Fatalf("buffered scanner expected ErrFileNameTooLong, got %v", err)
	}
	if len(spill) > maxNameLen || cap(spill) > maxNameLen {
		t.Fatalf("spill length/capacity = %d/%d, limit is %d", len(spill), cap(spill), maxNameLen)
	}
}

func TestReaderLimits_HeaderFieldsRespectDeclaredSize(t *testing.T) {
	tests := []struct {
		name         string
		headerTail   []byte
		declaredSize int
	}{
		{
			name:         "unterminated key",
			headerTail:   []byte("key\x00\x00"),
			declaredSize: len("key"),
		},
		{
			name:         "unterminated value",
			headerTail:   []byte("key\x00value\x00\x00"),
			declaredSize: len("key\x00value"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make([]byte, headerSize)
			binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))
			raw := append(header, test.headerTail...)
			declaredSize := int64(headerSize + test.declaredSize)
			ra := &syntheticReaderAt{prefix: raw, size: int64(len(raw))}

			_, err := NewReaderFromReaderAt(ra, declaredSize)
			if err == nil {
				t.Fatal("expected truncated header field error")
			}
			if ra.maxReadEnd > declaredSize {
				t.Fatalf("reader accessed byte %d beyond declared size %d", ra.maxReadEnd, declaredSize)
			}
		})
	}
}

func TestReaderLimits_HeaderAndEntryCount(t *testing.T) {
	entries := [][]byte{[]byte("a.txt"), []byte("b.txt")}
	raw := makeReaderLimitFixture([]HeaderPair{
		{Key: "key", Value: "value"},
		{Key: "other", Value: "value"},
	}, entries)

	_, err := NewReaderFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxEntries: 1},
	})
	if !errors.Is(err, ErrReaderLimitExceeded) {
		t.Fatalf("expected ErrReaderLimitExceeded for entry count, got %v", err)
	}
	_, err = ListEntriesFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxEntries: 1},
	})
	if !errors.Is(err, ErrReaderLimitExceeded) {
		t.Fatalf("list API expected ErrReaderLimitExceeded for entry count, got %v", err)
	}

	_, err = NewReaderFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxHeaderFieldBytes: 2},
	})
	if !errors.Is(err, ErrReaderLimitExceeded) {
		t.Fatalf("expected ErrReaderLimitExceeded for header field, got %v", err)
	}

	_, err = NewReaderFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxHeaderProperties: 1},
	})
	if !errors.Is(err, ErrReaderLimitExceeded) {
		t.Fatalf("expected ErrReaderLimitExceeded for header property count, got %v", err)
	}

	_, err = NewReaderFromReaderAtWithOptions(bytes.NewReader(raw), int64(len(raw)), ReaderOptions{
		Limits: ReaderLimits{MaxHeaderSectionBytes: 1},
	})
	if !errors.Is(err, ErrReaderLimitExceeded) {
		t.Fatalf("expected ErrReaderLimitExceeded for header section, got %v", err)
	}
}

func TestReader_PreservesRawControlAndInvalidUTF8EntryName(t *testing.T) {
	name := []byte{0xff, 0x01, 'x'}
	raw := makeReaderLimitFixture(nil, [][]byte{name})
	r, err := NewReaderFromReaderAt(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open raw-name fixture: %v", err)
	}
	defer func() { _ = r.Close() }()
	if got := []byte(r.EntriesView()[0].Path); !bytes.Equal(got, name) {
		t.Fatalf("raw name changed: got %v, want %v", got, name)
	}
}

// makeReaderLimitFixture encodes a small raw PBO index for parser limit tests.
func makeReaderLimitFixture(headers []HeaderPair, entryNames [][]byte) []byte {
	data := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(data[1:5], uint32(MimeHeader))
	for _, pair := range headers {
		data = append(data, pair.Key...)
		data = append(data, 0)
		data = append(data, pair.Value...)
		data = append(data, 0)
	}
	data = append(data, 0)
	for _, name := range entryNames {
		data = append(data, name...)
		data = append(data, 0)
		data = append(data, make([]byte, 20)...)
	}
	data = append(data, 0)
	data = append(data, make([]byte, 20)...)

	return data
}

// syntheticReaderAt generates a fixed prefix and repeated fill bytes without a large fixture allocation.
type syntheticReaderAt struct {
	prefix     []byte // Fixed bytes at the beginning of the source.
	size       int64  // Reported source size.
	maxReadEnd int64  // Furthest byte returned to the caller.
	fill       byte   // Repeated byte used after prefix.
}

// ReadAt generates bytes and records the furthest source position accessed.
func (r *syntheticReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative offset")
	}
	if offset >= r.size {
		return 0, io.EOF
	}
	n := len(p)
	if remaining := r.size - offset; int64(n) > remaining {
		n = int(remaining)
	}
	for i := 0; i < n; i++ {
		position := offset + int64(i)
		if position < int64(len(r.prefix)) {
			p[i] = r.prefix[position]
		} else {
			p[i] = r.fill
		}
	}
	if end := offset + int64(n); end > r.maxReadEnd {
		r.maxReadEnd = end
	}
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

func TestOpen_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pbo")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Open(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestOpenWithOptions_StoredOffsetCompatReadsGappedPayload(t *testing.T) {
	t.Parallel()

	path, firstOffset, secondOffset := createManualPBOWithAbsoluteOffsetsAndGaps(t)

	rDefault, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rDefault.Close() }()

	gotDefault, err := rDefault.ReadEntry("a.txt")
	if err != nil {
		t.Fatalf("ReadEntry default: %v", err)
	}
	if bytes.Equal(gotDefault, []byte("hello")) {
		t.Fatal("default sequential mode unexpectedly read stored-offset payload")
	}

	rCompat, err := OpenWithOptions(path, ReaderOptions{OffsetMode: OffsetModeStoredCompat})
	if err != nil {
		t.Fatalf("OpenWithOptions compat: %v", err)
	}
	defer func() { _ = rCompat.Close() }()

	entries := rCompat.Entries()
	if len(entries) != 2 {
		t.Fatalf("len(entries)=%d, want 2", len(entries))
	}
	if entries[0].Offset != firstOffset {
		t.Fatalf("entries[0].Offset=%d, want %d", entries[0].Offset, firstOffset)
	}
	if entries[1].Offset != secondOffset {
		t.Fatalf("entries[1].Offset=%d, want %d", entries[1].Offset, secondOffset)
	}

	listed, err := ListEntriesWithOptions(path, ReaderOptions{OffsetMode: OffsetModeStoredCompat})
	if err != nil {
		t.Fatalf("ListEntriesWithOptions compat: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("len(listed)=%d, want 2", len(listed))
	}
	if listed[0].Offset != firstOffset || listed[1].Offset != secondOffset {
		t.Fatalf("listed offsets = [%d, %d], want [%d, %d]", listed[0].Offset, listed[1].Offset, firstOffset, secondOffset)
	}

	gotA, err := rCompat.ReadEntry("a.txt")
	if err != nil {
		t.Fatalf("ReadEntry a.txt compat: %v", err)
	}
	if !bytes.Equal(gotA, []byte("hello")) {
		t.Fatalf("a.txt compat=%q, want hello", gotA)
	}

	gotB, err := rCompat.ReadEntry("b.txt")
	if err != nil {
		t.Fatalf("ReadEntry b.txt compat: %v", err)
	}
	if !bytes.Equal(gotB, []byte("world")) {
		t.Fatalf("b.txt compat=%q, want world", gotB)
	}
}

func TestOpenWithOptions_StoredOffsetStrictRejectsMalformed(t *testing.T) {
	t.Parallel()

	path := createManualPBOMalformedStoredOffset(t)

	rCompat, err := OpenWithOptions(path, ReaderOptions{OffsetMode: OffsetModeStoredCompat})
	if err != nil {
		t.Fatalf("OpenWithOptions compat: %v", err)
	}
	defer func() { _ = rCompat.Close() }()

	got, err := rCompat.ReadEntry("a.txt")
	if err != nil {
		t.Fatalf("ReadEntry compat: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("compat payload=%q, want hello", got)
	}

	_, err = OpenWithOptions(path, ReaderOptions{OffsetMode: OffsetModeStoredStrict})
	if !errors.Is(err, ErrInvalidEntryOffset) {
		t.Fatalf("expected ErrInvalidEntryOffset, got %v", err)
	}
}

func TestOpenWithOptions_JunkFilter(t *testing.T) {
	t.Parallel()

	path := createManualPBOWithJunkEntries(t)

	rDefault, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rDefault.Close() }()

	if len(rDefault.Entries()) != 5 {
		t.Fatalf("default entries=%d, want 5", len(rDefault.Entries()))
	}

	entries, err := rDefault.EntriesWithOptions(EntryViewOptions{FilterJunk: true})
	if err != nil {
		t.Fatalf("EntriesWithOptions junk filter: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("filtered entries=%d, want 2", len(entries))
	}
	if entries[0].Path != "keep1.txt" || entries[1].Path != "keep2.txt" {
		t.Fatalf("filtered paths = [%q, %q], want [keep1.txt, keep2.txt]", entries[0].Path, entries[1].Path)
	}

	got, err := rDefault.ReadEntry("keep2.txt")
	if err != nil {
		t.Fatalf("ReadEntry keep2.txt: %v", err)
	}
	if !bytes.Equal(got, []byte("world")) {
		t.Fatalf("keep2.txt payload = %q, want world", got)
	}

	listed, err := ListEntriesWithOptions(path, ReaderOptions{})
	if err != nil {
		t.Fatalf("ListEntriesWithOptions: %v", err)
	}
	if len(listed) != 5 {
		t.Fatalf("listed entries=%d, want raw count 5", len(listed))
	}
}

func TestReadHeaders_DoesNotRequireValidEntryTable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "headers-only.pbo")
	raw := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(raw[1:5], uint32(MimeHeader))

	// Header terminator.
	raw = append(raw, 0x00)
	// Broken entry table content (name without full 20-byte field block).
	raw = append(raw, 'a', 0x00, 0x01, 0x02, 0x03)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write pbo: %v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("Open must fail on malformed entry table")
	}

	headers, err := ReadHeaders(path)
	if err != nil {
		t.Fatalf("ReadHeaders: %v", err)
	}

	if len(headers) != 0 {
		t.Fatalf("len(headers)=%d, want 0", len(headers))
	}
}

func TestListEntries_MatchesOpenEntries(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "list.pbo")
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
			},
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 2048))), nil
			},
			SizeHint: 2048,
		},
	}

	opts := PackOptions{
		Compress: includeRules("*.txt"),
	}
	if _, err := PackFile(context.Background(), outPath, inputs, opts); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	want := r.Entries()
	got, err := ListEntries(outPath)
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("len(got)=%d, want %d", len(got), len(want))
	}

	for i := range want {
		if got[i].Path != want[i].Path {
			t.Fatalf("entry %d path=%q, want %q", i, got[i].Path, want[i].Path)
		}
		if got[i].Offset != want[i].Offset {
			t.Fatalf("entry %d offset=%d, want %d", i, got[i].Offset, want[i].Offset)
		}
		if got[i].DataSize != want[i].DataSize {
			t.Fatalf("entry %d size=%d, want %d", i, got[i].DataSize, want[i].DataSize)
		}
		if got[i].OriginalSize != want[i].OriginalSize {
			t.Fatalf("entry %d original=%d, want %d", i, got[i].OriginalSize, want[i].OriginalSize)
		}
		if got[i].MimeType != want[i].MimeType {
			t.Fatalf("entry %d mime=%v, want %v", i, got[i].MimeType, want[i].MimeType)
		}
	}
}

func TestReadEntry_NotFound(t *testing.T) {
	pboPath := createManualPBO(t, []byte("hello"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	_, err = r.ReadEntry("nonexistent.txt")
	if err == nil {
		t.Fatal("expected error for missing entry")
	}
	if !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("expected ErrEntryNotFound, got %v", err)
	}
}

func TestPackRoundTrip(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
			},
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("world"))), nil
			},
		},
	}

	opts := PackOptions{
		Headers: []HeaderPair{{Key: "prefix", Value: "test"}},
	}

	_, err = Pack(context.Background(), f, inputs, opts)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() < 80 {
		t.Fatalf("Pack wrote %d bytes (expected ≥80)", fi.Size())
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	r.file = f
	r.ra = f

	entries := r.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	gotA, err := r.ReadEntry("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, []byte("hello")) {
		t.Errorf("a.txt: got %q", gotA)
	}

	gotB, err := r.ReadEntry("b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotB, []byte("world")) {
		t.Errorf("b.txt: got %q", gotB)
	}
}

func TestReadEntry_NormalizedPathSeparators(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.pbo")
	inputs := []Input{
		{
			Path: "metricz/scripts/5_Mission/MetricZ/MissionServer.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("class CfgMission {};\n"))), nil
			},
		},
	}

	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	want := []byte("class CfgMission {};\n")
	withSlash, err := r.ReadEntry("metricz/scripts/5_Mission/MetricZ/MissionServer.c")
	if err != nil {
		t.Fatalf("ReadEntry with slash: %v", err)
	}
	if !bytes.Equal(withSlash, want) {
		t.Fatalf("ReadEntry with slash got %q", withSlash)
	}

	withBackslash, err := r.ReadEntry(`metricz\scripts\5_Mission\MetricZ\MissionServer.c`)
	if err != nil {
		t.Fatalf("ReadEntry with backslash: %v", err)
	}
	if !bytes.Equal(withBackslash, want) {
		t.Fatalf("ReadEntry with backslash got %q", withBackslash)
	}
}

func TestPack_NormalizesPrefixHeaderValue(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("ok"))), nil
			},
		},
	}

	_, err = Pack(context.Background(), f, inputs, PackOptions{
		Headers: []HeaderPair{{Key: "prefix", Value: "metricz/scripts/5_Mission"}},
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	r, err := NewReaderFromReaderAt(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	r.file = f
	r.ra = f
	defer func() { _ = r.Close() }()

	headers := r.Headers()
	if len(headers) != 1 {
		t.Fatalf("len(headers)=%d, want 1", len(headers))
	}

	if headers[0].Key != "prefix" {
		t.Fatalf("headers[0].Key=%q, want prefix", headers[0].Key)
	}

	if headers[0].Value != `metricz\scripts\5_Mission` {
		t.Fatalf("headers[0].Value=%q, want metricz\\scripts\\5_Mission", headers[0].Value)
	}
}

func TestExtractRoundTrip(t *testing.T) {
	pboPath := createManualPBO(t, []byte("hello"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	extDir := t.TempDir()
	if err := r.Extract(context.Background(), extDir, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatal(err)
	}

	gotA, err := os.ReadFile(filepath.Join(extDir, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, []byte("hello")) {
		t.Errorf("extracted a.txt: got %q", gotA)
	}
}

func TestExtract_DefaultModeRewritesExistingFiles(t *testing.T) {
	t.Parallel()

	pboPath := createManualPBO(t, []byte("hello"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	extDir := t.TempDir()
	if err := r.Extract(context.Background(), extDir, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatalf("first extract: %v", err)
	}

	targetPath := filepath.Join(extDir, "a.txt")
	if err := os.WriteFile(targetPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	if err := r.Extract(context.Background(), extDir, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatalf("second extract: %v", err)
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("rewritten file = %q, want hello", got)
	}

	err = r.Extract(context.Background(), extDir, ExtractOptions{
		MaxWorkers: 2,
		FileMode:   ExtractFileModeCreateOnly,
	})
	if err == nil {
		t.Fatal("expected create-only error for existing output file")
	}
	if !os.IsExist(err) && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("expected already-exists error, got %v", err)
	}
}

func TestExtract_DefaultFailFastStopsAfterFirstError(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "multi.pbo")
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("A"))), nil
			},
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("B"))), nil
			},
		},
	}

	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	extDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(extDir, "a.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale a.txt: %v", err)
	}

	err = r.Extract(context.Background(), extDir, ExtractOptions{
		MaxWorkers: 1,
		FileMode:   ExtractFileModeCreateOnly,
	})
	if err == nil {
		t.Fatal("expected create-only extraction error")
	}

	if !os.IsExist(err) && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("expected already-exists error, got %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(extDir, "b.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("b.txt must not be extracted in fail-fast mode, stat err = %v", statErr)
	}
}

func TestExtract_ContinueOnErrorExtractsRemainingEntries(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "multi.pbo")
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("A"))), nil
			},
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("B"))), nil
			},
		},
	}

	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	extDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(extDir, "a.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale a.txt: %v", err)
	}

	err = r.Extract(context.Background(), extDir, ExtractOptions{
		MaxWorkers:      1,
		FileMode:        ExtractFileModeCreateOnly,
		ContinueOnError: true,
	})
	if err == nil {
		t.Fatal("expected create-only extraction error")
	}

	if !os.IsExist(err) && !errors.Is(err, fs.ErrExist) {
		t.Fatalf("expected already-exists error, got %v", err)
	}

	got, readErr := os.ReadFile(filepath.Join(extDir, "b.txt"))
	if readErr != nil {
		t.Fatalf("read extracted b.txt: %v", readErr)
	}
	if !bytes.Equal(got, []byte("B")) {
		t.Fatalf("b.txt = %q, want B", got)
	}
}

func TestExtract_OverwriteSmart_TruncatesOnlyWhenNeeded(t *testing.T) {
	t.Parallel()

	pboPath := createManualPBO(t, []byte("hello"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	extDir := t.TempDir()
	targetPath := filepath.Join(extDir, "a.txt")

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}

	// Existing larger file must be truncated to extracted size.
	if err := os.WriteFile(targetPath, []byte("hello-with-tail"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	if err := r.Extract(context.Background(), extDir, ExtractOptions{
		MaxWorkers: 2,
		FileMode:   ExtractFileModeOverwriteSmart,
	}); err != nil {
		t.Fatalf("extract overwrite_smart: %v", err)
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("overwrite_smart output = %q, want hello", got)
	}

	// Existing equal-size file should also be rewritten successfully.
	if err := os.WriteFile(targetPath, []byte("HELLO"), 0o600); err != nil {
		t.Fatalf("write same-size stale file: %v", err)
	}

	if err := r.Extract(context.Background(), extDir, ExtractOptions{
		MaxWorkers: 2,
		FileMode:   ExtractFileModeOverwriteSmart,
	}); err != nil {
		t.Fatalf("extract overwrite_smart second run: %v", err)
	}

	got, err = os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read extracted file second run: %v", err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("overwrite_smart second output = %q, want hello", got)
	}
}

func TestExtract_RejectsUnsafeEntryPaths(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		entryPath string
	}{
		{name: "dot-dot slash", entryPath: "../evil.txt"},
		{name: "dot-dot backslash", entryPath: `..\evil.txt`},
		{name: "absolute slash", entryPath: "/absolute.txt"},
		{name: "absolute backslash", entryPath: `\absolute.txt`},
		{name: "windows drive", entryPath: `C:\absolute.txt`},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pboPath := createManualPBOWithEntryPath(t, tc.entryPath, []byte("hello"))
			r, err := Open(pboPath)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = r.Close() }()

			extDir := t.TempDir()
			err = r.Extract(context.Background(), extDir, ExtractOptions{
				MaxWorkers: 2,
				RawNames:   true,
			})
			if err == nil {
				t.Fatalf("expected extraction error for entry path %q", tc.entryPath)
			}
			if !errors.Is(err, ErrInvalidExtractPath) {
				t.Fatalf("expected ErrInvalidExtractPath, got %v", err)
			}
		})
	}
}

func TestExtract_SanitizesUnsafeEntryPaths(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		entryPath string
		wantPath  string
	}{
		{name: "dot-dot slash", entryPath: "../evil.txt", wantPath: filepath.Join("_", "evil.txt")},
		{name: "dot-dot backslash", entryPath: `..\evil.txt`, wantPath: filepath.Join("_", "evil.txt")},
		{name: "absolute slash", entryPath: "/absolute.txt", wantPath: "absolute.txt"},
		{name: "absolute backslash", entryPath: `\absolute.txt`, wantPath: "absolute.txt"},
		{name: "windows drive", entryPath: `C:\absolute.txt`, wantPath: filepath.Join("C_", "absolute.txt")},
		{name: "mangled separators", entryPath: `\\\\\:\`, wantPath: "_"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pboPath := createManualPBOWithEntryPath(t, tc.entryPath, []byte("hello"))
			r, err := Open(pboPath)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = r.Close() }()

			extDir := t.TempDir()
			if err := r.Extract(context.Background(), extDir, ExtractOptions{MaxWorkers: 2}); err != nil {
				t.Fatalf("Extract sanitize: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(extDir, tc.wantPath))
			if err != nil {
				t.Fatalf("read sanitized file %s: %v", tc.wantPath, err)
			}
			if !bytes.Equal(got, []byte("hello")) {
				t.Fatalf("sanitized output %s=%q, want hello", tc.wantPath, got)
			}
		})
	}
}

func TestReadEntry_CompressedCorruptedPayload(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "compressed.pbo")
	payload := bytes.Repeat([]byte("abcdef"), 1024)
	inputs := []Input{
		{
			Path: "a.bin",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}
	opts := PackOptions{
		Compress:        includeRules("*"),
		MinCompressSize: 1,
		MaxCompressSize: 32 * 1024 * 1024,
	}

	if _, err := PackFile(context.Background(), outPath, inputs, opts); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	entries := r.Entries()
	if len(entries) != 1 {
		_ = r.Close()
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if !entries[0].IsCompressed() {
		_ = r.Close()
		t.Fatal("entry is expected to be compressed")
	}
	_ = r.Close()

	f, err := os.OpenFile(outPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open for patch: %v", err)
	}

	corruptOffset := int64(entries[0].Offset) + int64(entries[0].DataSize) - 1
	if _, err := f.Seek(corruptOffset, io.SeekStart); err != nil {
		_ = f.Close()
		t.Fatalf("seek: %v", err)
	}
	b := []byte{0}
	if _, err := f.Read(b); err != nil {
		_ = f.Close()
		t.Fatalf("read byte: %v", err)
	}
	if _, err := f.Seek(corruptOffset, io.SeekStart); err != nil {
		_ = f.Close()
		t.Fatalf("seek back: %v", err)
	}
	b[0] ^= 0xFF
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		t.Fatalf("write byte: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close patched file: %v", err)
	}

	r, err = Open(outPath)
	if err != nil {
		t.Fatalf("Open after corrupt: %v", err)
	}
	defer func() { _ = r.Close() }()

	_, err = r.ReadEntry("a.bin")
	if err == nil {
		t.Fatal("expected decompression error for corrupted compressed payload")
	}
}

func TestCheckSHA1Trailer(t *testing.T) {
	pboPath := createMinimalPBO(t)
	hash, err := checkSHA1TrailerForTest(pboPath)
	if err != nil {
		t.Fatalf("checkSHA1TrailerForTest: %v", err)
	}
	if hash == [20]byte{} {
		t.Error("expected non-zero hash")
	}

	r, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	got, ok := r.SHA1Trailer()
	if !ok || got != hash {
		t.Fatalf("SHA1Trailer() = (%x, %t), want (%x, true)", got, ok, hash)
	}
	hashSet, err := computeHashSetFromReader(r, SignVersionV2, GameTypeArma)
	if err != nil {
		t.Fatalf("computeHashSetFromReader: %v", err)
	}
	if hashSet.Hash1 != hash {
		t.Fatalf("hash1 = %x, want trailer digest %x", hashSet.Hash1, hash)
	}
}

func TestPack_EmptyInputs(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.pbo")
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Pack(context.Background(), f, nil, PackOptions{})
	_ = f.Close()
	if err == nil {
		t.Fatal("expected error for empty inputs")
	}
	if !errors.Is(err, ErrEmptyInputs) {
		t.Errorf("expected ErrEmptyInputs, got %v", err)
	}
}

func TestPack_WritesZeroEntryOffsets(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "offsets.pbo")
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
			},
		},
		{
			Path: "b.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("world"))), nil
			},
		},
	}

	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open pbo: %v", err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("stat pbo: %v", err)
	}

	off := int64(headerSize)

	for {
		key, n, err := readNullTerminated(f, fi.Size(), off, defaultMaxHeaderFieldBytes, ErrReaderLimitExceeded)
		if err != nil {
			t.Fatalf("read header key at %d: %v", off, err)
		}

		off += int64(n)
		if key == "" {
			break
		}

		_, n, err = readNullTerminated(f, fi.Size(), off, defaultMaxHeaderFieldBytes, ErrReaderLimitExceeded)
		if err != nil {
			t.Fatalf("read header value at %d: %v", off, err)
		}

		off += int64(n)
	}

	for {
		name, n, err := readNullTerminated(f, fi.Size(), off, maxNameLen, ErrReaderLimitExceeded)
		if err != nil {
			t.Fatalf("read entry name at %d: %v", off, err)
		}

		off += int64(n)
		fields := make([]byte, 20)
		if _, err := f.ReadAt(fields, off); err != nil {
			t.Fatalf("read entry fields at %d: %v", off, err)
		}

		off += int64(len(fields))
		mime := binary.LittleEndian.Uint32(fields[0:4])
		offset := binary.LittleEndian.Uint32(fields[8:12])
		size := binary.LittleEndian.Uint32(fields[16:20])

		if name == "" && mime == 0 && size == 0 {
			break
		}

		if offset != 0 {
			t.Fatalf("entry %q has non-zero offset field: %d", name, offset)
		}
	}

	if off >= fi.Size() {
		t.Fatalf("unexpected data start offset %d for file size %d", off, fi.Size())
	}
}

func createMinimalPBO(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "minimal.pbo")
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello"))), nil
			},
		},
	}
	_, err := PackFile(context.Background(), outPath, inputs, PackOptions{})
	if err != nil {
		t.Fatalf("createMinimalPBO: %v", err)
	}
	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("createMinimalPBO stat: %v", err)
	}
	// Expect at least: 22 header + 27 first entry + 21 null entry + 5 payload = 75, plus 21 trailer = 96
	if fi.Size() < 70 {
		t.Fatalf("createMinimalPBO: file too small (%d bytes)", fi.Size())
	}
	return outPath
}

// createManualPBOWithJunkEntries writes a handcrafted PBO with valid and junk entries.
func createManualPBOWithJunkEntries(t *testing.T) string {
	t.Helper()

	type entrySpec struct {
		name         string
		mime         MimeType
		originalSize uint32
		data         []byte
	}

	specs := []entrySpec{
		{name: "keep1.txt", mime: MimeNil, data: []byte("hello")},
		{name: "zero.bin", mime: MimeNil, data: nil},
		{name: "badcprs.bin", mime: MimeCompress, originalSize: 0, data: []byte{1, 2, 3, 4}},
		{name: "../evil.txt", mime: MimeNil, data: []byte("bad")},
		{name: "keep2.txt", mime: MimeNil, data: []byte("world")},
	}

	path := filepath.Join(t.TempDir(), "junk.pbo")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pbo: %v", err)
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

	for _, spec := range specs {
		if _, err := f.Write([]byte(spec.name + "\x00")); err != nil {
			_ = f.Close()
			t.Fatalf("write name: %v", err)
		}

		fields := make([]byte, 20)
		binary.LittleEndian.PutUint32(fields[0:4], uint32(spec.mime))
		binary.LittleEndian.PutUint32(fields[4:8], spec.originalSize)
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(spec.data)))
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

	for _, spec := range specs {
		if len(spec.data) == 0 {
			continue
		}

		if _, err := f.Write(spec.data); err != nil {
			_ = f.Close()
			t.Fatalf("write payload: %v", err)
		}
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close pbo: %v", err)
	}

	return path
}

// createManualPBOWithAbsoluteOffsetsAndGaps writes a handcrafted PBO where payloads start at stored absolute offsets.
func createManualPBOWithAbsoluteOffsetsAndGaps(t *testing.T) (string, uint32, uint32) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "offset-compat.pbo")
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))

	var table bytes.Buffer
	writeEntry := func(name string) int {
		_, _ = table.WriteString(name)
		_ = table.WriteByte(0)
		fieldPos := table.Len()
		_, _ = table.Write(make([]byte, 20))
		return fieldPos
	}

	fieldPosA := writeEntry("a.txt")
	fieldPosB := writeEntry("b.txt")
	_ = table.WriteByte(0)
	_, _ = table.Write(make([]byte, 20))

	raw := make([]byte, 0, 256)
	raw = append(raw, header...)
	raw = append(raw, 0x00)
	tableBase := len(raw)
	raw = append(raw, table.Bytes()...)
	dataStart := len(raw)

	firstOffset := uint32(dataStart + 16)
	secondOffset := firstOffset + uint32(len("hello")+7)

	binary.LittleEndian.PutUint32(raw[tableBase+fieldPosA+8:tableBase+fieldPosA+12], firstOffset)
	binary.LittleEndian.PutUint32(raw[tableBase+fieldPosA+16:tableBase+fieldPosA+20], uint32(len("hello")))
	binary.LittleEndian.PutUint32(raw[tableBase+fieldPosB+8:tableBase+fieldPosB+12], secondOffset)
	binary.LittleEndian.PutUint32(raw[tableBase+fieldPosB+16:tableBase+fieldPosB+20], uint32(len("world")))

	regionLen := int(secondOffset) + len("world") - dataStart
	region := make([]byte, regionLen)
	copy(region[int(firstOffset)-dataStart:], []byte("hello"))
	copy(region[int(secondOffset)-dataStart:], []byte("world"))
	raw = append(raw, region...)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write pbo: %v", err)
	}

	return path, firstOffset, secondOffset
}

// createManualPBOMalformedStoredOffset writes a handcrafted PBO with out-of-file stored offset.
func createManualPBOMalformedStoredOffset(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "offset-strict-malformed.pbo")
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[1:5], uint32(MimeHeader))

	var table bytes.Buffer
	_, _ = table.WriteString("a.txt")
	_ = table.WriteByte(0)
	fieldPos := table.Len()
	_, _ = table.Write(make([]byte, 20))
	_ = table.WriteByte(0)
	_, _ = table.Write(make([]byte, 20))

	raw := make([]byte, 0, 128)
	raw = append(raw, header...)
	raw = append(raw, 0x00)
	tableBase := len(raw)
	raw = append(raw, table.Bytes()...)

	binary.LittleEndian.PutUint32(raw[tableBase+fieldPos+8:tableBase+fieldPos+12], 0xFFFFFFF0)
	binary.LittleEndian.PutUint32(raw[tableBase+fieldPos+16:tableBase+fieldPos+20], uint32(len("hello")))
	raw = append(raw, []byte("hello")...)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write pbo: %v", err)
	}

	return path
}

package pbo

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Test mirrors format SHA1 hashing pipeline.
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestComputeHashSet_FileHashUsesPackedBytes(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("class MissionServer { void Tick(); }\n"), 128)
	pboPath := createCompressedSignFixturePBO(t, payload)

	r, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", pboPath, err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if !entries[0].IsCompressed() {
		t.Fatalf("entry %q must be compressed for this regression", entries[0].Path)
	}

	hs, err := ComputeHashSet(pboPath, SignVersionV3, GameTypeDayZ)
	if err != nil {
		t.Fatalf("ComputeHashSet(%s): %v", pboPath, err)
	}

	nameHash := computeSignNameHash(entries)
	prefix := pboPrefixFromHeaders(r.Headers())
	fileHashPacked, err := computePackedFileHashForTest(r, entries, SignVersionV3, GameTypeDayZ)
	if err != nil {
		t.Fatalf("computePackedFileHashForTest(): %v", err)
	}

	wantHash3 := computeSignHash3(fileHashPacked, nameHash, prefix)
	if !bytes.Equal(hs.Hash3[:], wantHash3) {
		t.Fatalf("hash3 mismatch:\n got  %x\n want %x", hs.Hash3, wantHash3)
	}

	fileHashDecompressed, err := computeDecompressedFileHashForTest(r, entries, SignVersionV3, GameTypeDayZ)
	if err != nil {
		t.Fatalf("computeDecompressedFileHashForTest(): %v", err)
	}

	legacyHash3 := computeSignHash3(fileHashDecompressed, nameHash, prefix)
	if bytes.Equal(hs.Hash3[:], legacyHash3) {
		t.Fatalf("hash3 must not match decompressed-content legacy logic: %x", legacyHash3)
	}
}

func TestComputeHashSet_FileHashUsesStoredEntryOrder(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "hashset-order.pbo")
	inputs := []Input{
		{
			Path: "a.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("lower-a"))), nil
			},
			SizeHint: int64(len("lower-a")),
		},
		{
			Path: "B.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("upper-b"))), nil
			},
			SizeHint: int64(len("upper-b")),
		},
	}

	_, err := PackFile(context.Background(), outPath, inputs, PackOptions{
		Compress:        includeRules("*.c"),
		MinCompressSize: 1,
	})
	if err != nil {
		t.Fatalf("PackFile(%s): %v", outPath, err)
	}

	hs, err := ComputeHashSet(outPath, SignVersionV3, GameTypeDayZ)
	if err != nil {
		t.Fatalf("ComputeHashSet(%s): %v", outPath, err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open(%s): %v", outPath, err)
	}
	defer func() { _ = r.Close() }()

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open %s: %v", outPath, err)
	}
	defer func() { _ = f.Close() }()

	entries := r.Entries()
	prefix := pboPrefixFromHeaders(r.Headers())
	nameHash := computeSignNameHash(entries)

	fileHashStoredOrder, err := computePackedFileHashForTestUsingOrder(f, entries, SignVersionV3, GameTypeDayZ, false)
	if err != nil {
		t.Fatalf("stored-order filehash: %v", err)
	}

	wantHash3 := computeSignHash3(fileHashStoredOrder, nameHash, prefix)
	if !bytes.Equal(hs.Hash3[:], wantHash3) {
		t.Fatalf("hash3 mismatch for stored order:\n got  %x\n want %x", hs.Hash3, wantHash3)
	}

	fileHashLowerOrder, err := computePackedFileHashForTestUsingOrder(f, entries, SignVersionV3, GameTypeDayZ, true)
	if err != nil {
		t.Fatalf("lower-order filehash: %v", err)
	}

	legacyHash3 := computeSignHash3(fileHashLowerOrder, nameHash, prefix)
	if bytes.Equal(hs.Hash3[:], legacyHash3) {
		t.Fatalf("hash3 must not match lower-case sorted filehash order: %x", legacyHash3)
	}
}

func TestComputeSignNameHash_DeduplicatesNormalizedNames(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "config.bin", DataSize: 120},
		{Path: "CONFIG.BIN", DataSize: 80},      // duplicate after lower-case normalize
		{Path: "scripts/Thing.c", DataSize: 64}, // duplicate after slash normalize + lower-case
		{Path: "scripts\\thing.c", DataSize: 32},
		{Path: "skip-zero.bin", DataSize: 0},
		{Path: "", DataSize: 10},
	}

	got := computeSignNameHash(entries)

	wantNames := []string{
		"config.bin",
		"scripts\\thing.c",
	}
	sort.Strings(wantNames)

	h := sha1.New() //nolint:gosec // Test mirrors namehash SHA1 behavior.
	for _, n := range wantNames {
		_, _ = h.Write([]byte(n))
	}
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("namehash mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestComputeSignNameHash_UsesASCIILowercase(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "scripts/Ä.c", DataSize: 8},
		{Path: "scripts/ä.c", DataSize: 8},
	}

	got := computeSignNameHash(entries)

	wantNames := []string{
		"scripts\\Ä.c",
		"scripts\\ä.c",
	}
	sort.Strings(wantNames)

	h := sha1.New() //nolint:gosec // Test mirrors namehash SHA1 behavior.
	for _, n := range wantNames {
		_, _ = h.Write([]byte(n))
	}
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("namehash mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestShouldHashFileForSign_DayZV3Policy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{name: "c", filename: "scripts/mission.c", want: true},
		{name: "cfg", filename: "config.cfg", want: true},
		{name: "cpp", filename: "config.cpp", want: false},
		{name: "rtm", filename: "anim.rtm", want: false},
		{name: "hpp", filename: "defs.hpp", want: true},
		{name: "h", filename: "defs.h", want: true},
		{name: "inc", filename: "defs.inc", want: true},
		{name: "ext", filename: "mission.ext", want: true},
		{name: "bikb", filename: "briefing.bikb", want: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := shouldHashFileForSign(SignVersionV3, GameTypeDayZ, tt.filename)
			if err != nil {
				t.Fatalf("shouldHashFileForSign(dayz, %q): %v", tt.filename, err)
			}

			if got != tt.want {
				t.Fatalf("shouldHashFileForSign(dayz, %q)=%t, want %t", tt.filename, got, tt.want)
			}
		})
	}
}

// createCompressedSignFixturePBO creates a one-entry PBO where hashed file payload is compressed.
func createCompressedSignFixturePBO(t *testing.T, payload []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hashset-packed.pbo")
	entryPath := "scripts/5_Mission/MetricZ/MissionServer.c"
	inputs := []Input{
		{
			Path: entryPath,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	_, err := PackFile(context.Background(), path, inputs, PackOptions{
		Compress:        includeRules(entryPath),
		MinCompressSize: 1,
	})
	if err != nil {
		t.Fatalf("PackFile(%s): %v", path, err)
	}

	return path
}

// computePackedFileHashForTest mirrors filehash rules over packed payload bytes.
func computePackedFileHashForTest(r *Reader, entries []EntryInfo, version SignVersion, gameType GameType) ([]byte, error) {
	f, ok := r.ra.(*os.File)
	if !ok {
		return nil, ErrNilReader
	}

	return computePackedFileHashForTestUsingOrder(f, entries, version, gameType, true)
}

// computePackedFileHashForTestUsingOrder hashes packed payload with selectable file order.
func computePackedFileHashForTestUsingOrder(
	f *os.File,
	entries []EntryInfo,
	version SignVersion,
	gameType GameType,
	useLowerCaseSort bool,
) ([]byte, error) {
	sorted := make([]EntryInfo, len(entries))
	copy(sorted, entries)
	if useLowerCaseSort {
		sort.Slice(sorted, func(i, j int) bool {
			n1 := strings.ToLower(strings.ReplaceAll(sorted[i].Path, "/", "\\"))
			n2 := strings.ToLower(strings.ReplaceAll(sorted[j].Path, "/", "\\"))
			return n1 < n2
		})
	}

	h := sha1.New() //nolint:gosec // Test mirrors filehash SHA1 behavior.
	hashedAny := false
	for _, e := range sorted {
		if e.Path == "" || e.DataSize == 0 {
			continue
		}

		ok, err := shouldHashFileForSign(version, gameType, e.Path)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		sr := io.NewSectionReader(f, int64(e.Offset), int64(e.DataSize))
		if _, err := io.Copy(h, sr); err != nil {
			return nil, err
		}

		hashedAny = true
	}

	if !hashedAny {
		if version == 2 {
			_, _ = h.Write([]byte("nothing"))
		} else {
			_, _ = h.Write([]byte("gnihton"))
		}
	}

	return h.Sum(nil), nil
}

// computeDecompressedFileHashForTest replicates the legacy incorrect filehash over decompressed payload.
func computeDecompressedFileHashForTest(r *Reader, entries []EntryInfo, version SignVersion, gameType GameType) ([]byte, error) {
	sorted := make([]EntryInfo, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		n1 := strings.ToLower(strings.ReplaceAll(sorted[i].Path, "/", "\\"))
		n2 := strings.ToLower(strings.ReplaceAll(sorted[j].Path, "/", "\\"))
		return n1 < n2
	})

	h := sha1.New() //nolint:gosec // Test mirrors filehash SHA1 behavior.
	hashedAny := false
	for _, e := range sorted {
		if e.Path == "" || e.DataSize == 0 {
			continue
		}

		ok, err := shouldHashFileForSign(version, gameType, e.Path)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		rc, err := r.OpenEntry(e.Path)
		if err != nil {
			return nil, err
		}

		if _, err := io.Copy(h, rc); err != nil {
			_ = rc.Close()
			return nil, err
		}

		_ = rc.Close()
		hashedAny = true
	}

	if !hashedAny {
		if version == 2 {
			_, _ = h.Write([]byte("nothing"))
		} else {
			_, _ = h.Write([]byte("gnihton"))
		}
	}

	return h.Sum(nil), nil
}

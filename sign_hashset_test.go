package pbo

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Test mirrors format SHA1 hashing pipeline.
	"encoding/hex"
	"errors"
	"fmt"
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
		Compress:        true,
		CompressRules:   includeRules("*.c"),
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

// TestComputeSignHashMatchesOriginalPrefixVectors checks original signer digests.
func TestComputeSignHashMatchesOriginalPrefixVectors(t *testing.T) {
	t.Parallel()

	hash1, err := hex.DecodeString("c4d8ecc9d1cdddb1e082e9b0afb228cd108384dc")
	if err != nil {
		t.Fatalf("decode original hash1: %v", err)
	}
	entries := []EntryInfo{
		{Path: "probe.c", DataSize: 5},
		{Path: "asset.paa", DataSize: 7},
	}
	nameHash := computeSignNameHash(entries)
	fileHashV2 := sha1.Sum([]byte("alpha"))       //nolint:gosec // Test mirrors the original fixture.
	fileHashArmaV3 := sha1.Sum([]byte("gnihton")) //nolint:gosec // Empty V3 filehash sentinel.
	prefix := pboPrefixFromHeaders([]HeaderPair{{Key: PropertyPrefix, Value: `some\folder`}})

	if got := fmt.Sprintf(
		"%x", computeSignHash2(hash1, nameHash, prefix),
	); got != "4169b4f387a5c05620aca336c921460ee8759be7" {
		t.Fatalf("hash2=%s, want original signer hash2", got)
	}
	if got := fmt.Sprintf(
		"%x", computeSignHash3(fileHashV2[:], nameHash, prefix),
	); got != "3e4611b08121364ece2895eec3c13aae1d3b3a7a" {
		t.Fatalf("V2 hash3=%s, want original signer hash3", got)
	}
	if got := fmt.Sprintf(
		"%x", computeSignHash3(fileHashArmaV3[:], nameHash, prefix),
	); got != "f547a2079f8f9d5a4b4741499a24b1869fbbc967" {
		t.Fatalf("Arma V3 hash3=%s, want original signer hash3", got)
	}
}

// TestPboPrefixFromHeadersNormalizesSigningPrefix checks canonical signing bytes.
func TestPboPrefixFromHeadersNormalizesSigningPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		present bool
		want    string
	}{
		{name: "forward separators", prefix: "some/folder", present: true, want: `some\folder`},
		{name: "trailing forward separator", prefix: "some/folder/", present: true, want: `some\folder`},
		{name: "trailing backward separator", prefix: `some\folder\`, present: true, want: `some\folder`},
		{name: "mixed separators", prefix: `some/folder\child`, present: true, want: `some\folder\child`},
		{name: "absent", want: ""},
		{name: "empty", prefix: "", present: true, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			headers := []HeaderPair(nil)
			if test.present {
				headers = []HeaderPair{{Key: PropertyPrefix, Value: test.prefix}}
			}
			gotPrefix := pboPrefixFromHeaders(headers)
			if gotPrefix != test.want {
				t.Fatalf("pboPrefixFromHeaders(%q)=%q, want %q", test.prefix, gotPrefix, test.want)
			}

			var gotFragment bytes.Buffer
			writeSignPrefix(&gotFragment, gotPrefix)
			wantFragment := test.want
			if wantFragment != "" {
				wantFragment += `\`
			}
			if gotFragment.String() != wantFragment {
				t.Fatalf("signing prefix=%q, want %q", gotFragment.String(), wantFragment)
			}
		})
	}
}

// TestComputeHashSetNormalizesPrefixSeparators verifies normalization through Reader.
func TestComputeHashSetNormalizesPrefixSeparators(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "prefix.pbo")
	inputs := []Input{{
		Path: "probe.c",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("alpha"))), nil
		},
		SizeHint: int64(len("alpha")),
	}}
	if _, err := PackFile(context.Background(), path, inputs, PackOptions{
		Headers: []HeaderPair{{Key: PropertyPrefix, Value: `some\folder`}},
	}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	value := []byte(`some\folder`)
	valueOffset := bytes.Index(data, value)
	if valueOffset < 0 {
		t.Fatal("packed prefix not found")
	}
	for i := range value {
		if value[i] == '\\' {
			data[valueOffset+i] = '/'
		}
	}

	bodyEnd := len(data) - 21
	digest := sha1.Sum(data[:bodyEnd]) //nolint:gosec // Test mirrors PBO trailer hashing.
	data[bodyEnd] = 0
	copy(data[bodyEnd+1:], digest[:])
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	storedPrefix, _ := propertyValue(r.Headers(), PropertyPrefix)
	if storedPrefix != "some/folder" {
		t.Fatalf("stored prefix=%q, want raw forward-slash value", storedPrefix)
	}
	if got := pboPrefixFromHeaders(r.Headers()); got != `some\folder` {
		t.Fatalf("signing prefix=%q, want canonical backslashes", got)
	}

	hashSet, err := ComputeHashSet(path, SignVersionV2, GameTypeDayZ)
	if err != nil {
		t.Fatalf("ComputeHashSet: %v", err)
	}

	entries := r.Entries()
	nameHash := computeSignNameHash(entries)
	wantHash2 := computeSignHash2(hashSet.Hash1[:], nameHash, `some\folder`)
	if !bytes.Equal(hashSet.Hash2[:], wantHash2) {
		t.Fatalf("hash2=%x, want canonical-prefix hash %x", hashSet.Hash2, wantHash2)
	}

	fileHash, err := computeSignFileHashFromReaderAt(r.ra, entries, SignVersionV2, GameTypeDayZ)
	if err != nil {
		t.Fatalf("computeSignFileHashFromReaderAt: %v", err)
	}

	wantHash3 := computeSignHash3(fileHash, nameHash, `some\folder`)
	if !bytes.Equal(hashSet.Hash3[:], wantHash3) {
		t.Fatalf("hash3=%x, want canonical-prefix hash %x", hashSet.Hash3, wantHash3)
	}
}

// TestShouldHashFileForSign_Policies covers the complete game/version extension policy.
func TestShouldHashFileForSign_Policies(t *testing.T) {
	t.Parallel()

	policies := []struct {
		name     string
		version  SignVersion
		gameType GameType
		included []string
		excluded []string
	}{
		{
			name:     "arma-v2",
			version:  SignVersionV2,
			gameType: GameTypeArma,
			included: []string{"cpp", "nm", "xob", "anm", "edds", "emat", "ptc", "sqfc", "c", "sqf"},
			excluded: []string{"paa", "jpg", "p3d", "tga", "rvmat", "lip", "ogg", "wss", "png", "rtm", "pac", "fxy", "wrp"},
		},
		{
			name:     "dayz-v2",
			version:  SignVersionV2,
			gameType: GameTypeDayZ,
			included: []string{"cpp", "sqfc", "c", "sqf"},
			excluded: []string{
				"paa", "jpg", "p3d", "tga", "rvmat", "lip", "ogg", "wss", "png",
				"rtm", "pac", "fxy", "wrp", "nm", "xob", "anm", "edds", "emat", "ptc",
			},
		},
		{
			name:     "arma-v3",
			version:  SignVersionV3,
			gameType: GameTypeArma,
			included: []string{"sqf", "inc", "bikb", "ext", "fsm", "sqm", "hpp", "cfg", "sqs", "h", "sqfc"},
			excluded: []string{"cpp", "c", "nm", "paa", "unknown"},
		},
		{
			name:     "dayz-v3",
			version:  SignVersionV3,
			gameType: GameTypeDayZ,
			included: []string{"inc", "bikb", "ext", "hpp", "cfg", "h", "c"},
			excluded: []string{"cpp", "sqf", "fsm", "sqm", "sqs", "sqfc", "nm", "paa", "unknown"},
		},
	}

	for _, policy := range policies {
		t.Run(policy.name, func(t *testing.T) {
			t.Parallel()

			for _, ext := range policy.included {
				filename := "scripts/asset." + ext
				got, err := shouldHashFileForSign(policy.version, policy.gameType, filename)
				if err != nil {
					t.Fatalf("shouldHashFileForSign(%s, %q): %v", policy.name, filename, err)
				}
				if !got {
					t.Errorf("shouldHashFileForSign(%s, %q)=false, want true", policy.name, filename)
				}
			}

			for _, ext := range policy.excluded {
				filename := "scripts/asset." + ext
				got, err := shouldHashFileForSign(policy.version, policy.gameType, filename)
				if err != nil {
					t.Fatalf("shouldHashFileForSign(%s, %q): %v", policy.name, filename, err)
				}
				if got {
					t.Errorf("shouldHashFileForSign(%s, %q)=true, want false", policy.name, filename)
				}
			}

			for _, filename := range []string{"no-extension", "asset.", "asset.sqfcx", "scripts\\asset.C"} {
				want := policy.version == SignVersionV2
				if filename == "scripts\\asset.C" && policy.version == SignVersionV3 {
					want = policy.gameType == GameTypeDayZ
				}
				got, err := shouldHashFileForSign(policy.version, policy.gameType, filename)
				if err != nil {
					t.Fatalf("shouldHashFileForSign(%s, %q): %v", policy.name, filename, err)
				}
				if got != want {
					t.Errorf("shouldHashFileForSign(%s, %q)=%t, want %t", policy.name, filename, got, want)
				}
			}
		})
	}
}

// TestValidateSignHashArgsRequiresGameType rejects missing and unknown game policies.
func TestValidateSignHashArgsRequiresGameType(t *testing.T) {
	t.Parallel()

	for _, version := range []SignVersion{SignVersionV2, SignVersionV3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			t.Parallel()

			for _, gameType := range []GameType{"", "unknown"} {
				if err := validateSignHashArgs(version, gameType); !errors.Is(err, ErrUnsupportedGameType) {
					t.Errorf("validateSignHashArgs(%d, %q) error=%v, want ErrUnsupportedGameType", version, gameType, err)
				}
			}

			if err := validateSignHashArgs(version, GameType("DAYZ")); err != nil {
				t.Errorf("validateSignHashArgs(%d, DAYZ): %v", version, err)
			}
		})
	}

	if err := validateSignHashArgs(SignVersion(1), GameTypeDayZ); !errors.Is(err, ErrUnsupportedSignVersion) {
		t.Fatalf("validateSignHashArgs(1, dayz) error=%v, want ErrUnsupportedSignVersion", err)
	}
}

// TestComputeSignFileHashFromReaderAtRequiresGameTypeForEmptyEntries validates empty input too.
func TestComputeSignFileHashFromReaderAtRequiresGameTypeForEmptyEntries(t *testing.T) {
	t.Parallel()

	_, err := computeSignFileHashFromReaderAt(bytes.NewReader(nil), nil, SignVersionV2, "")
	if !errors.Is(err, ErrUnsupportedGameType) {
		t.Fatalf("error=%v, want ErrUnsupportedGameType", err)
	}
}

// TestComputeSignFileHashEmptySentinels preserves version-specific empty filehash values.
func TestComputeSignFileHashEmptySentinels(t *testing.T) {
	t.Parallel()

	for _, version := range []SignVersion{SignVersionV2, SignVersionV3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			t.Parallel()

			payload := "nothing"
			if version == SignVersionV3 {
				payload = "gnihton"
			}
			want := sha1.Sum([]byte(payload))

			for _, entries := range [][]EntryInfo{nil, {{Path: "empty.c", DataSize: 0}}} {
				for _, gameType := range []GameType{GameTypeArma, GameTypeDayZ} {
					got, err := computeSignFileHashFromReaderAt(
						bytes.NewReader(nil),
						entries,
						version,
						gameType,
					)
					if err != nil {
						t.Fatalf("computeSignFileHashFromReaderAt(%d, %s): %v", version, gameType, err)
					}
					if !bytes.Equal(got, want[:]) {
						t.Errorf("empty filehash for %d/%s=%x, want %x", version, gameType, got, want)
					}
				}
			}
		})
	}
}

// TestComputeHashSet_GameTypeOnlyChangesV2Hash3 keeps hash1/hash2 game-independent.
func TestComputeHashSet_GameTypeOnlyChangesV2Hash3(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "game-policy.pbo")
	inputs := []Input{
		{
			Path: "asset.nm",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("nm-payload"))), nil
			},
			SizeHint: int64(len("nm-payload")),
		},
	}
	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatalf("PackFile(%s): %v", outPath, err)
	}

	armaHashes, err := ComputeHashSet(outPath, SignVersionV2, GameTypeArma)
	if err != nil {
		t.Fatalf("ComputeHashSet(Arma V2): %v", err)
	}
	dayZHashes, err := ComputeHashSet(outPath, SignVersionV2, GameTypeDayZ)
	if err != nil {
		t.Fatalf("ComputeHashSet(DayZ V2): %v", err)
	}

	if armaHashes.Hash1 != dayZHashes.Hash1 || armaHashes.Hash2 != dayZHashes.Hash2 {
		t.Fatal("hash1 and hash2 changed with game type")
	}
	if armaHashes.Hash3 == dayZHashes.Hash3 {
		t.Fatal("hash3 did not change with V2 game-specific file selection")
	}
}

// TestComputeHashSetRequiresExplicitGameType rejects a missing game before opening the PBO.
func TestComputeHashSetRequiresExplicitGameType(t *testing.T) {
	t.Parallel()

	_, err := ComputeHashSet(filepath.Join(t.TempDir(), "missing.pbo"), SignVersionV2, "")
	if !errors.Is(err, ErrUnsupportedGameType) {
		t.Fatalf("ComputeHashSet() error=%v, want ErrUnsupportedGameType", err)
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
		Compress:        true,
		CompressRules:   includeRules(entryPath),
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

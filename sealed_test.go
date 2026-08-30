package pbo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestPackFileAndOpenWithOptions_SealedKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key := sealedTestKey()
	plainPath := filepath.Join(t.TempDir(), "plain.pbo")
	sealedPath := filepath.Join(t.TempDir(), "sealed.pbo")
	inputs := []Input{
		{
			Path: "scripts/main.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(
					bytes.Repeat([]byte("class X {};\n"), 256),
				)), nil
			},
			SizeHint: int64(len(bytes.Repeat([]byte("class X {};\n"), 256))),
		},
		{
			Path: "config.cpp",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("class CfgPatches {};"))), nil
			},
			SizeHint: int64(len("class CfgPatches {};")),
		},
	}

	packOpts := PackOptions{
		Headers: []HeaderPair{
			{Key: "prefix", Value: "test/mod"},
		},
		Compress: includeRules("*.c"),
	}

	if _, err := PackFile(context.Background(), plainPath, inputs, packOpts); err != nil {
		t.Fatalf("PackFile plain: %v", err)
	}

	sealedOpts := packOpts
	sealedOpts.SealedKey = &key
	if _, err := PackFile(context.Background(), sealedPath, inputs, sealedOpts); err != nil {
		t.Fatalf("PackFile sealed: %v", err)
	}

	plainData, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read plain file: %v", err)
	}

	sealedData, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("read sealed file: %v", err)
	}

	if bytes.Equal(plainData, sealedData) {
		t.Fatal("sealed output must differ from plain output")
	}

	r, err := OpenWithOptions(sealedPath, ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("OpenWithOptions sealed: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 2 {
		t.Fatalf("len(entries)=%d, want 2", len(entries))
	}
	trailer, ok := r.SHA1Trailer()
	if !ok {
		t.Fatal("SHA1Trailer() did not verify the sealed archive trailer")
	}
	hashSet, err := computeHashSetFromReader(r, SignVersionV2, GameTypeArma)
	if err != nil {
		t.Fatalf("computeHashSetFromReader: %v", err)
	}
	if hashSet.Hash1 != trailer {
		t.Fatalf("sealed hash1 = %x, want trailer digest %x", hashSet.Hash1, trailer)
	}

	data, err := r.ReadEntry("config.cpp")
	if err != nil {
		t.Fatalf("ReadEntry config.cpp: %v", err)
	}
	if string(data) != "class CfgPatches {};" {
		t.Fatalf("config.cpp payload=%q, want class CfgPatches {};", data)
	}

	listed, err := ListEntriesWithOptions(sealedPath, ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("ListEntriesWithOptions sealed: %v", err)
	}

	if len(listed) != 2 {
		t.Fatalf("len(listed)=%d, want 2", len(listed))
	}

	forced, err := OpenWithOptions(sealedPath, ReaderOptions{
		SealedKey:   &key,
		TrailerMode: TrailerModePresent,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions forced trailer: %v", err)
	}
	_ = forced.Close()
}

func TestSealedTrailerDetection_NoTrailerZeroCandidate(t *testing.T) {
	t.Parallel()

	key := sealedTestKey()
	path := filepath.Join(t.TempDir(), "sealed-no-trailer.pbo")
	payload := bytes.Repeat([]byte{0x42}, 128)
	if _, err := PackFile(context.Background(), path, []Input{{
		Path: "payload.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}}, PackOptions{SealedKey: &key}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	body := data[:len(data)-sealedTrailerSize]
	body[len(body)-sealedTrailerSize] = 0
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write no-trailer fixture: %v", err)
	}

	r, err := OpenWithOptions(path, ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("OpenWithOptions auto trailer: %v", err)
	}
	if entries := r.Entries(); len(entries) != 1 || entries[0].Path != "payload.bin" {
		_ = r.Close()
		t.Fatalf("Entries() = %#v, want payload.bin", entries)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close auto reader: %v", err)
	}

	r, err = OpenWithOptions(path, ReaderOptions{
		SealedKey:   &key,
		TrailerMode: TrailerModeAbsent,
	})
	if err != nil {
		t.Fatalf("OpenWithOptions forced absent: %v", err)
	}
	_ = r.Close()
}

func TestSealedKey_NilIsNoop(t *testing.T) {
	t.Parallel()

	raw := []byte("abc")
	got := append([]byte(nil), raw...)
	if err := applySealedTransformInPlace(got, nil); err != nil {
		t.Fatalf("applySealedTransformInPlace nil key: %v", err)
	}

	if !bytes.Equal(got, raw) {
		t.Fatal("nil sealed key must keep bytes unchanged")
	}
}

func TestSealedTransformBatched_MatchesSegmentTransformAndRoundTrips(t *testing.T) {
	t.Parallel()

	basePath := filepath.Join(t.TempDir(), "base.pbo")
	if _, err := PackFile(context.Background(), basePath, []Input{{
		Path: "payload.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("payload"))), nil
		},
	}}, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}
	base, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	key := sealedTestKey()
	for _, size := range []int{
		sealedBlockSize - 1,
		sealedBlockSize,
		sealedBlockSize + 1,
		sealedIOBatchSize - 1,
		sealedIOBatchSize,
		sealedIOBatchSize + 1,
		2*sealedIOBatchSize - 1,
		2 * sealedIOBatchSize,
		2*sealedIOBatchSize + 1,
	} {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			original := make([]byte, size)
			copy(original, base)
			for i := len(base); i < len(original); i++ {
				original[i] = byte(i * 31)
			}

			want := append([]byte(nil), original...)
			if err := applySealedTransformBySegments(want, &key); err != nil {
				t.Fatalf("reference transform: %v", err)
			}

			got := append([]byte(nil), original...)
			if err := applySealedTransformToReadWriteAt(
				bytes.NewReader(original), testWriterAt{data: got}, int64(len(got)), &key, false,
			); err != nil {
				t.Fatalf("batched transform: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("batched transform differs from segment reference")
			}

			if err := applySealedTransformToReadWriteAt(
				bytes.NewReader(got), testWriterAt{data: got}, int64(len(got)), &key, false,
			); err != nil {
				t.Fatalf("second batched transform: %v", err)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("double transform did not restore original bytes")
			}
		})
	}
}

// applySealedTransformBySegments preserves the pre-batching algorithm for byte-level comparison.
func applySealedTransformBySegments(data []byte, keyValue *SealedKey) error {
	key := parseSealedKey(keyValue)
	layout, err := buildSealedLayoutWithOptions(bytes.NewReader(data), int64(len(data)), TrailerModeAbsent, ReaderLimits{})
	if err != nil {
		return err
	}

	transformSegment := func(segmentStart int64, segmentEnd int64, streamPos uint32) {
		segment := data[int(segmentStart):int(segmentEnd)]
		state := newSealedRC4StateForStreamPos(key, layout.seed, streamPos)
		state.swapIndices()
		state.apply(segment)
	}

	firstEnd := minInt64(sealedBlockSize, layout.transformSize)
	if layout.headerSkip < firstEnd {
		transformSegment(layout.headerSkip, firstEnd, 0)
	}
	for segmentStart := int64(sealedBlockSize); segmentStart < layout.transformSize; segmentStart += sealedBlockSize {
		segmentEnd := minInt64(segmentStart+sealedBlockSize, layout.transformSize)
		streamPos, err := checkedInt64ToUint32(segmentStart)
		if err != nil {
			return err
		}

		transformSegment(segmentStart, segmentEnd, streamPos)
	}

	return nil
}

// testWriterAt updates the byte slice used by sealed transform tests.
type testWriterAt struct {
	data []byte
}

// WriteAt copies bytes into the test buffer at the requested offset.
func (w testWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(w.data)) {
		return 0, io.ErrShortWrite
	}

	return copy(w.data[int(off):], p), nil
}

func TestEditorCommit_SealedKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key := sealedTestKey()
	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	err := createTestPBO(pboPath, map[string][]byte{
		"a.txt": []byte("old-a"),
		"b.txt": []byte("keep-b"),
	}, PackOptions{
		SealedKey: &key,
	})
	if err != nil {
		t.Fatalf("createTestPBO sealed: %v", err)
	}

	editor, err := OpenEditor(pboPath, EditOptions{
		PackOptions: PackOptions{
			SealedKey: &key,
		},
		BackupKeep: 0,
	})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}

	if err := editor.Replace(Input{
		Path: "a.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("new-a"))), nil
		},
		SizeHint: int64(len("new-a")),
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit sealed: %v", err)
	}

	r, err := OpenWithOptions(pboPath, ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("OpenWithOptions sealed: %v", err)
	}
	defer func() { _ = r.Close() }()

	gotA, err := r.ReadEntry("a.txt")
	if err != nil {
		t.Fatalf("ReadEntry a.txt: %v", err)
	}
	if string(gotA) != "new-a" {
		t.Fatalf("a.txt payload=%q, want new-a", gotA)
	}

	gotB, err := r.ReadEntry("b.txt")
	if err != nil {
		t.Fatalf("ReadEntry b.txt: %v", err)
	}
	if string(gotB) != "keep-b" {
		t.Fatalf("b.txt payload=%q, want keep-b", gotB)
	}
}

func TestSealedTransform_RandomBytesRoundTrip(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	rng := rand.New(rand.NewSource(42))
	inputs := []Input{
		{
			Path: "scripts/main.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(
					bytes.Repeat([]byte("class X {};\n"), 128),
				)), nil
			},
			SizeHint: int64(len(bytes.Repeat([]byte("class X {};\n"), 128))),
		},
		{
			Path: "config.cpp",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("class CfgPatches {};"))), nil
			},
			SizeHint: int64(len("class CfgPatches {};")),
		},
	}

	for i := 0; i < 64; i++ {
		pboPath := filepath.Join(baseDir, fmt.Sprintf("random-%d.pbo", i))
		f, err := os.OpenFile(pboPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("open output file: %v", err)
		}

		if _, err := Pack(context.Background(), f, inputs, PackOptions{}); err != nil {
			_ = f.Close()
			t.Fatalf("Pack: %v", err)
		}

		if err := f.Close(); err != nil {
			t.Fatalf("close output file: %v", err)
		}

		original, err := os.ReadFile(pboPath)
		if err != nil {
			t.Fatalf("read original archive: %v", err)
		}

		var key SealedKey
		if _, err := rng.Read(key[:]); err != nil {
			t.Fatalf("rng.Read key: %v", err)
		}

		transformed := append([]byte(nil), original...)
		if err := applySealedTransformInPlace(transformed, &key); err != nil {
			t.Fatalf("first transform: %v", err)
		}

		if err := applySealedTransformInPlace(transformed, &key); err != nil {
			t.Fatalf("second transform: %v", err)
		}

		if !bytes.Equal(transformed, original) {
			t.Fatalf("iteration %d: roundtrip mismatch", i)
		}
	}
}

func sealedTestKey() SealedKey {
	var key SealedKey
	copy(key[:], []byte("test-sealed-key!"))

	return key
}

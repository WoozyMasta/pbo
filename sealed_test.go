// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
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
		Compress:      true,
		CompressRules: includeRules("*.c"),
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
	if sealedData[len(sealedData)-sealedTrailerSize] == 0 {
		t.Fatal("sealed transform did not transform the PBO trailer marker")
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

	var storedDigest [sealedDigestSize]byte
	copy(storedDigest[:], sealedData[len(sealedData)-sealedDigestSize:])
	if trailer != storedDigest {
		t.Fatalf("SHA1 trailer = %x, want unchanged digest %x", trailer, storedDigest)
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

func TestPackAndHashWithSealedKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key := sealedTestKey()
	inputs := []Input{{
		Path: "payload.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("payload"))), nil
		},
		SizeHint: int64(len("payload")),
	}}
	options := PackOptions{SealedKey: &key}

	t.Run("PackAndHash", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "archive.pbo")
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatalf("OpenFile: %v", err)
		}
		if _, _, err := PackAndHash(
			context.Background(), file, inputs, options, SignVersionV3, GameTypeDayZ,
		); err != nil {
			_ = file.Close()
			t.Fatalf("PackAndHash: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		reader, err := OpenWithOptions(path, ReaderOptions{SealedKey: &key})
		if err != nil {
			t.Fatalf("OpenWithOptions: %v", err)
		}
		defer func() { _ = reader.Close() }()

		got, err := reader.ReadEntry("payload.bin")
		if err != nil {
			t.Fatalf("ReadEntry: %v", err)
		}
		if string(got) != "payload" {
			t.Fatalf("payload = %q, want payload", got)
		}
	})

	t.Run("PackAndHashFile", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "archive.pbo")
		_, hashes, err := PackAndHashFile(
			context.Background(), path, inputs, options, SignVersionV3, GameTypeDayZ,
		)
		if err != nil {
			t.Fatalf("PackAndHashFile: %v", err)
		}

		reader, err := OpenWithOptions(path, ReaderOptions{SealedKey: &key})
		if err != nil {
			t.Fatalf("OpenWithOptions: %v", err)
		}
		defer func() { _ = reader.Close() }()

		got, err := reader.ReadEntry("payload.bin")
		if err != nil {
			t.Fatalf("ReadEntry: %v", err)
		}
		if string(got) != "payload" {
			t.Fatalf("payload = %q, want payload", got)
		}

		trailer, ok := reader.SHA1Trailer()
		if !ok {
			t.Fatal("SHA1Trailer() did not verify")
		}
		if hashes.Hash1 != trailer {
			t.Fatalf("hash1 = %x, want verified trailer %x", hashes.Hash1, trailer)
		}
	})
}

func TestSealedTransform_LargeHeaderCrossesBlockBoundary(t *testing.T) {
	t.Parallel()

	key := sealedTestKey()
	path := filepath.Join(t.TempDir(), "large-header.pbo")
	plainPath := filepath.Join(t.TempDir(), "large-header-plain.pbo")
	packPath := filepath.Join(t.TempDir(), "large-header-pack.pbo")
	plainPackPath := filepath.Join(t.TempDir(), "large-header-pack-plain.pbo")
	inputs := []Input{{
		Path: "payload.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("payload"))), nil
		},
		SizeHint: int64(len("payload")),
	}}
	options := PackOptions{
		Headers: []HeaderPair{{
			Key:   "metadata",
			Value: strings.Repeat("x", sealedBlockSize+128),
		}},
	}
	if _, err := PackFile(context.Background(), plainPath, inputs, options); err != nil {
		t.Fatalf("PackFile plain: %v", err)
	}

	options.SealedKey = &key
	if _, err := PackFile(context.Background(), path, inputs, options); err != nil {
		t.Fatalf("PackFile sealed: %v", err)
	}

	plainData, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("ReadFile plain: %v", err)
	}
	if err := applySealedTransformBySegments(plainData, &key); err != nil {
		t.Fatalf("reference transform: %v", err)
	}

	sealedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile sealed: %v", err)
	}
	if !bytes.Equal(sealedData, plainData) {
		t.Fatal("sealed output differs from block-aligned reference transform")
	}

	plainPackFile, err := os.OpenFile(plainPackPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile plain Pack output: %v", err)
	}
	if _, err := Pack(
		context.Background(), plainPackFile, inputs, PackOptions{Headers: options.Headers},
	); err != nil {
		_ = plainPackFile.Close()
		t.Fatalf("Pack plain: %v", err)
	}
	if err := plainPackFile.Close(); err != nil {
		t.Fatalf("Close plain Pack output: %v", err)
	}

	plainPackData, err := os.ReadFile(plainPackPath)
	if err != nil {
		t.Fatalf("ReadFile plain Pack output: %v", err)
	}
	if err := applySealedTransformBySegments(plainPackData, &key); err != nil {
		t.Fatalf("reference transform plain Pack output: %v", err)
	}

	packFile, err := os.OpenFile(packPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile Pack output: %v", err)
	}
	if _, err := Pack(context.Background(), packFile, inputs, options); err != nil {
		_ = packFile.Close()
		t.Fatalf("Pack sealed: %v", err)
	}
	if err := packFile.Close(); err != nil {
		t.Fatalf("Close Pack output: %v", err)
	}

	packData, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatalf("ReadFile Pack output: %v", err)
	}
	if !bytes.Equal(packData, plainPackData) {
		t.Fatal("Pack output differs from block-aligned reference transform")
	}

	reader, err := OpenWithOptions(path, ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("OpenWithOptions: %v", err)
	}
	defer func() { _ = reader.Close() }()

	got, err := reader.ReadEntry("payload.bin")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("payload = %q, want payload", got)
	}
	if _, ok := reader.SHA1Trailer(); !ok {
		t.Fatal("SHA1Trailer() did not verify large-header archive")
	}
	if _, err := ReadHeadersWithOptions(path, ReaderOptions{
		SealedKey:   &key,
		TrailerMode: TrailerModePresent,
	}); err != nil {
		t.Fatalf("ReadHeadersWithOptions: %v", err)
	}
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
	}}, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	body := data[:len(data)-sealedTrailerSize]
	body[len(body)-sealedTrailerSize] = 0
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatalf("open fixture directory: %v", err)
	}
	defer func() { _ = root.Close() }()

	if err := root.WriteFile(filepath.Base(path), body, 0o600); err != nil {
		t.Fatalf("write no-trailer fixture: %v", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fixture for sealed transform: %v", err)
	}
	if err := ToggleSealedInPlace(file, &key); err != nil {
		_ = file.Close()
		t.Fatalf("ToggleSealedInPlace: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close transformed fixture: %v", err)
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
			t.Parallel()

			original := make([]byte, size)
			copy(original, base)
			for i := len(base); i < len(original); i++ {
				original[i] = original[i%len(base)]
			}

			want := append([]byte(nil), original...)
			if err := applySealedTransformBySegments(want, &key); err != nil {
				t.Fatalf("reference transform: %v", err)
			}

			got := append([]byte(nil), original...)
			if err := applySealedTransformToReadWriteAt(
				bytes.NewReader(original), testWriterAt{data: got}, int64(len(got)), &key,
			); err != nil {
				t.Fatalf("batched transform: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("batched transform differs from segment reference")
			}

			if err := applySealedTransformToReadWriteAt(
				bytes.NewReader(got), testWriterAt{data: got}, int64(len(got)), &key,
			); err != nil {
				t.Fatalf("second batched transform: %v", err)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("double transform did not restore original bytes")
			}
		})
	}
}

// applySealedTransformBySegments provides a block-aligned reference transform for tests.
func applySealedTransformBySegments(data []byte, keyValue *SealedKey) error {
	key := parseSealedKey(keyValue)
	layout, err := buildSealedLayout(bytes.NewReader(data), int64(len(data)), ReaderLimits{})
	if err != nil {
		return err
	}

	transformSegment := func(segmentStart int64, segmentEnd int64, streamPos uint32) {
		segment := data[int(segmentStart):int(segmentEnd)]
		state := newSealedRC4StateForStreamPos(key, layout.seed, streamPos)
		state.swapIndices()
		state.apply(segment)
	}

	for blockStart := int64(0); blockStart < layout.transformEnd; blockStart += sealedBlockSize {
		segmentStart := maxInt64(blockStart, layout.headerSkip)
		segmentEnd := minInt64(blockStart+sealedBlockSize, layout.transformEnd)
		if segmentStart >= segmentEnd {
			continue
		}
		streamPos, err := checkedInt64ToUint32(blockStart)
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
	rng := rand.New(rand.NewSource(42)) //nolint:gosec // Deterministic test keys keep failures reproducible.
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

	for i := range 64 {
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

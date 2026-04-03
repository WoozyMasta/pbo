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

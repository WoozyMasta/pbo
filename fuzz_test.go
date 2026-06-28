// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func FuzzNewReaderFromReaderAt(f *testing.F) {
	seed := buildFuzzSeedPBO(f)
	f.Add(seed)
	f.Add([]byte{})
	f.Add(seed[:5])
	f.Add(seed[:21])
	f.Add(seed[:headerSize])
	if len(seed) > headerSize+1 {
		f.Add(seed[:headerSize+1])
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReaderFromReaderAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		_ = r.Entries()
		_ = r.Close()
	})
}

func FuzzOpenEntry(f *testing.F) {
	seed := buildFuzzSeedPBO(f)
	f.Add(seed)
	f.Add([]byte{})
	f.Add(seed[:5])

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReaderFromReaderAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()

		for _, e := range r.Entries() {
			rc, err := r.OpenEntryInfo(e)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, rc)
			_ = rc.Close()
			break
		}
	})
}

func FuzzExtract(f *testing.F) {
	seed := buildFuzzSeedPBO(f)
	f.Add(seed)
	f.Add([]byte{})
	f.Add(seed[:5])

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReaderFromReaderAt(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		defer func() { _ = r.Close() }()

		dir := t.TempDir()
		_ = r.Extract(context.Background(), dir, ExtractOptions{MaxWorkers: 1})
	})
}

// buildFuzzSeedPBO builds a minimal valid PBO via PackFile and returns its bytes.
// Uses a real *os.File so Pack gets correct Seek semantics.
func buildFuzzSeedPBO(tb testing.TB) []byte {
	tb.Helper()

	dir := tb.TempDir()
	path := filepath.Join(dir, "seed.pbo")

	inputs := []Input{
		{
			Path: "fuzz/seed.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("hello fuzz"))), nil
			},
			SizeHint: 10,
		},
		{
			Path: "fuzz/compressed.cfg",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("compress me "), 50))), nil
			},
			SizeHint: 600,
		},
	}

	opts := PackOptions{
		Compress:        includeRules("*.cfg"),
		MinCompressSize: 1,
	}

	if _, err := PackFile(context.Background(), path, inputs, opts); err != nil {
		tb.Fatalf("build fuzz seed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		tb.Fatalf("read fuzz seed: %v", err)
	}

	return data
}

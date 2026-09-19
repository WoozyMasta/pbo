// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta

package pbo

import (
	"bytes"
	"context"
	"io"
	"math"
	"path/filepath"
	"testing"
)

func TestReadEntry_MatchesStreamingForRawCompressedAndEmpty(t *testing.T) {
	t.Parallel()

	compressed := bytes.Repeat([]byte("full-memory-read-compressed-payload"), 2048)
	openBytes := func(data []byte) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}
	}
	inputs := []Input{
		{
			Path:     "raw.bin",
			Open:     openBytes([]byte("raw payload")),
			SizeHint: int64(len("raw payload")),
		},
		{
			Path:     "compressed.bin",
			Open:     openBytes(compressed),
			SizeHint: int64(len(compressed)),
		},
		{Path: "empty.bin", Open: openBytes(nil)},
	}
	path := filepath.Join(t.TempDir(), "read-entry.pbo")
	if _, err := PackFile(context.Background(), path, inputs, PackOptions{
		Compress:        includeRules("compressed.bin"),
		MinCompressSize: 1,
	}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	for _, name := range []string{"raw.bin", "compressed.bin", "empty.bin"} {
		t.Run(name, func(t *testing.T) {
			stream, err := r.OpenEntry(name)
			if err != nil {
				t.Fatalf("OpenEntry: %v", err)
			}
			want, err := io.ReadAll(stream)
			_ = stream.Close()
			if err != nil {
				t.Fatalf("read stream: %v", err)
			}

			got, err := r.ReadEntry(name)
			if err != nil {
				t.Fatalf("ReadEntry: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("ReadEntry differs from stream: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

func TestCheckedUint32ToInt(t *testing.T) {
	t.Parallel()

	for _, value := range []uint32{0, 1, math.MaxInt32, math.MaxUint32} {
		got, err := checkedUint32ToInt(value)
		if uint64(value) > uint64(math.MaxInt) {
			if err != ErrSizeOverflow {
				t.Errorf("checkedUint32ToInt(%d) error=%v, want ErrSizeOverflow", value, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("checkedUint32ToInt(%d): %v", value, err)
			continue
		}
		if got != int(value) {
			t.Errorf("checkedUint32ToInt(%d)=%d, want %d", value, got, int(value))
		}
	}
}

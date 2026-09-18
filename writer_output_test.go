// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta

package pbo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPack_ResetsTruncatableOutput(t *testing.T) {
	t.Parallel()

	out := &truncatingMemoryOutput{memWriteSeeker: &memWriteSeeker{
		buf: bytes.Repeat([]byte{0xa5}, 4096),
		off: 37,
	}}
	if _, err := Pack(context.Background(), out, outputTestInputs(), PackOptions{}); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if out.off != int64(len(out.buf)) {
		t.Fatalf("output position=%d, length=%d", out.off, len(out.buf))
	}

	r, err := NewReaderFromReaderAt(bytes.NewReader(out.buf), int64(len(out.buf)))
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()
	got, err := r.ReadEntry("file.txt")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if string(got) != "new archive" {
		t.Fatalf("entry payload=%q, want %q", got, "new archive")
	}
}

func TestPack_RequiresEmptyNonTruncatableOutputAtOffsetZero(t *testing.T) {
	t.Parallel()

	t.Run("non-empty", func(t *testing.T) {
		t.Parallel()
		original := []byte("existing bytes")
		out := &memWriteSeeker{buf: append([]byte(nil), original...)}
		if _, err := Pack(context.Background(), out, outputTestInputs(), PackOptions{}); !errors.Is(err, ErrOutputNotEmpty) {
			t.Fatalf("Pack error=%v, want ErrOutputNotEmpty", err)
		}
		if !bytes.Equal(out.buf, original) || out.off != 0 {
			t.Fatalf("output changed: bytes=%q position=%d", out.buf, out.off)
		}
	})

	t.Run("non-zero position", func(t *testing.T) {
		t.Parallel()
		out := &memWriteSeeker{off: 1}
		if _, err := Pack(context.Background(), out, outputTestInputs(), PackOptions{}); !errors.Is(err, ErrOutputPosition) {
			t.Fatalf("Pack error=%v, want ErrOutputPosition", err)
		}
		if len(out.buf) != 0 || out.off != 1 {
			t.Fatalf("output changed: bytes=%q position=%d", out.buf, out.off)
		}
	})

	t.Run("empty sink", func(t *testing.T) {
		t.Parallel()
		out := &memWriteSeeker{}
		if _, err := Pack(context.Background(), out, outputTestInputs(), PackOptions{}); err != nil {
			t.Fatalf("Pack: %v", err)
		}
		if out.off != int64(len(out.buf)) {
			t.Fatalf("output position=%d, length=%d", out.off, len(out.buf))
		}
	})
}

func TestPackAndHash_ResetsTruncatableOutput(t *testing.T) {
	t.Parallel()

	out := &truncatingMemoryOutput{memWriteSeeker: &memWriteSeeker{
		buf: bytes.Repeat([]byte{0xa5}, 4096),
		off: 37,
	}}
	if _, _, err := PackAndHash(context.Background(), out, outputTestInputs(), PackOptions{}, SignVersionV3, GameTypeDayZ); err != nil {
		t.Fatalf("PackAndHash: %v", err)
	}
	if out.off != int64(len(out.buf)) {
		t.Fatalf("output position=%d, length=%d", out.off, len(out.buf))
	}
	if _, err := NewReaderFromReaderAt(out, int64(len(out.buf))); err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
}

func TestFilePack_FailuresPreserveExistingTarget(t *testing.T) {
	t.Parallel()

	packers := []struct {
		name string
		pack func(string, []Input, PackOptions) error
	}{
		{
			name: "PackFile",
			pack: func(path string, inputs []Input, opts PackOptions) error {
				_, err := PackFile(context.Background(), path, inputs, opts)
				return err
			},
		},
		{
			name: "PackAndHashFile",
			pack: func(path string, inputs []Input, opts PackOptions) error {
				_, _, err := PackAndHashFile(context.Background(), path, inputs, opts, SignVersionV3, GameTypeDayZ)
				return err
			},
		},
	}
	failures := []struct {
		name   string
		inputs []Input
		opts   PackOptions
		want   error
	}{
		{
			name:   "invalid path",
			inputs: []Input{{Path: "/", Open: outputTestInputs()[0].Open}},
			want:   ErrInvalidEntryPath,
		},
		{
			name:   "invalid property",
			inputs: outputTestInputs(),
			opts:   PackOptions{Headers: []HeaderPair{{Key: "key", Value: "bad\x00value"}}},
			want:   ErrInvalidHeaderProperty,
		},
		{
			name: "input open",
			inputs: []Input{{
				Path: "file.txt",
				Open: func() (io.ReadCloser, error) { return nil, errOutputInputOpen },
			}},
			want: errOutputInputOpen,
		},
		{
			name: "payload read",
			inputs: []Input{{
				Path: "file.txt",
				Open: func() (io.ReadCloser, error) { return &failingPayloadReader{}, nil },
			}},
			want: errOutputPayloadRead,
		},
	}

	for _, packer := range packers {
		for _, failure := range failures {
			t.Run(packer.name+"/"+failure.name, func(t *testing.T) {
				t.Parallel()
				path := filepath.Join(t.TempDir(), "existing.pbo")
				const original = "previous valid archive"
				if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
					t.Fatal(err)
				}

				if err := packer.pack(path, failure.inputs, failure.opts); !errors.Is(err, failure.want) {
					t.Fatalf("pack error=%v, want %v", err, failure.want)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read existing target: %v", err)
				}
				if string(got) != original {
					t.Fatalf("existing target changed to %q", got)
				}
				entries, err := os.ReadDir(filepath.Dir(path))
				if err != nil {
					t.Fatalf("ReadDir: %v", err)
				}
				if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
					t.Fatalf("temporary output files remain: %v", entries)
				}
			})
		}
	}
}

func TestFilePack_ReplacesExistingTargetWithVerifiedArchive(t *testing.T) {
	t.Parallel()

	packers := []struct {
		name string
		pack func(string, []Input) error
	}{
		{
			name: "PackFile",
			pack: func(path string, inputs []Input) error {
				_, err := PackFile(context.Background(), path, inputs, PackOptions{})
				return err
			},
		},
		{
			name: "PackAndHashFile",
			pack: func(path string, inputs []Input) error {
				_, _, err := PackAndHashFile(context.Background(), path, inputs, PackOptions{}, SignVersionV3, GameTypeDayZ)
				return err
			},
		},
	}

	for _, packer := range packers {
		t.Run(packer.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "existing.pbo")
			if err := os.WriteFile(path, []byte("old archive with trailing bytes"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := packer.pack(path, outputTestInputs()); err != nil {
				t.Fatalf("pack: %v", err)
			}

			r, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = r.Close() }()
			if _, ok := r.SHA1Trailer(); !ok {
				t.Fatal("replacement archive has no verified SHA1 trailer")
			}
			got, err := r.ReadEntry("file.txt")
			if err != nil {
				t.Fatalf("ReadEntry: %v", err)
			}
			if string(got) != "new archive" {
				t.Fatalf("entry payload=%q, want %q", got, "new archive")
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
				t.Fatalf("temporary or backup files remain: %v", entries)
			}
		})
	}
}

// outputTestInputs returns a repeatable minimal archive input.
func outputTestInputs() []Input {
	payload := []byte("new archive")
	return []Input{{
		Path: "file.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
		SizeHint: int64(len(payload)),
	}}
}

// truncatingMemoryOutput models a seekable memory target that can be reset and read back.
type truncatingMemoryOutput struct {
	*memWriteSeeker
}

// Truncate changes the length of the in-memory output.
func (m *truncatingMemoryOutput) Truncate(size int64) error {
	if size < 0 {
		return ErrSizeOverflow
	}
	if size <= int64(len(m.buf)) {
		m.buf = m.buf[:size]
	} else {
		m.buf = append(m.buf, make([]byte, size-int64(len(m.buf)))...)
	}
	if m.off > size {
		m.off = size
	}

	return nil
}

// ReadAt provides random access to the current in-memory output bytes.
func (m *truncatingMemoryOutput) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(m.buf).ReadAt(p, off)
}

var (
	// errOutputInputOpen is returned by the synthetic input opener.
	errOutputInputOpen = errors.New("test input open failure")
	// errOutputPayloadRead is returned after the synthetic reader yields partial data.
	errOutputPayloadRead = errors.New("test payload read failure")
)

// failingPayloadReader returns a partial payload and then a stable read error.
type failingPayloadReader struct {
	readPartial bool
}

// Read simulates an input stream failing after yielding some payload bytes.
func (r *failingPayloadReader) Read(p []byte) (int, error) {
	if r.readPartial {
		return 0, errOutputPayloadRead
	}
	r.readPartial = true

	return copy(p, []byte("partial payload")), nil
}

// Close satisfies io.ReadCloser for the synthetic payload reader.
func (r *failingPayloadReader) Close() error {
	return nil
}

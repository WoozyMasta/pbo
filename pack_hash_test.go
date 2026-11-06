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

func TestPackAndHash_MatchesComputeHashSet(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("class X {\n};\n"), 1024)
	inputs := []Input{
		{
			Path: "scripts/main.c",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	for _, gameType := range []GameType{GameTypeDayZ, GameTypeArma} {
		t.Run(string(gameType), func(t *testing.T) {
			t.Parallel()

			outPath := filepath.Join(t.TempDir(), "out.pbo")
			f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatalf("create file: %v", err)
			}
			defer func() { _ = f.Close() }()

			_, hsPack, err := PackAndHash(context.Background(), f, inputs, PackOptions{
				Compress:        true,
				CompressRules:   includeRules("*.c"),
				MinCompressSize: 1,
			}, SignVersionV3, gameType)
			if err != nil {
				t.Fatalf("PackAndHash: %v", err)
			}

			if err := f.Sync(); err != nil {
				t.Fatalf("sync: %v", err)
			}

			hsFile, err := ComputeHashSet(outPath, SignVersionV3, gameType)
			if err != nil {
				t.Fatalf("ComputeHashSet: %v", err)
			}

			if hsPack != hsFile {
				t.Fatalf("hash mismatch:\nPackAndHash=%x\nComputeHashSet=%x", hsPack, hsFile)
			}
		})
	}
}

func TestPackAndHashFile_MatchesComputeHashSet(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("x"), 64*1024)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		},
	}

	for _, gameType := range []GameType{GameTypeDayZ, GameTypeArma} {
		t.Run(string(gameType), func(t *testing.T) {
			t.Parallel()

			outPath := filepath.Join(t.TempDir(), "out.pbo")
			_, hsPack, err := PackAndHashFile(context.Background(), outPath, inputs, PackOptions{
				Compress:      true,
				CompressRules: includeRules("*.txt"),
			}, SignVersionV2, gameType)
			if err != nil {
				t.Fatalf("PackAndHashFile: %v", err)
			}

			hsFile, err := ComputeHashSet(outPath, SignVersionV2, gameType)
			if err != nil {
				t.Fatalf("ComputeHashSet: %v", err)
			}

			if hsPack != hsFile {
				t.Fatalf("hash mismatch:\nPackAndHashFile=%x\nComputeHashSet=%x", hsPack, hsFile)
			}
		})
	}
}

// TestPackAndHashRequiresExplicitGameType checks both streaming pack-and-hash APIs.
func TestPackAndHashRequiresExplicitGameType(t *testing.T) {
	t.Parallel()

	inputs := []Input{{
		Path: "a.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("abc"))), nil
		},
		SizeHint: 3,
	}}

	_, _, err := PackAndHash(
		context.Background(), &memWriteSeeker{}, inputs, PackOptions{}, SignVersionV2, "",
	)
	if !errors.Is(err, ErrUnsupportedGameType) {
		t.Fatalf("PackAndHash() error=%v, want ErrUnsupportedGameType", err)
	}

	_, _, err = PackAndHashFile(
		context.Background(),
		filepath.Join(t.TempDir(), "missing-game.pbo"),
		inputs,
		PackOptions{},
		SignVersionV2,
		"",
	)
	if !errors.Is(err, ErrUnsupportedGameType) {
		t.Fatalf("PackAndHashFile() error=%v, want ErrUnsupportedGameType", err)
	}
}

// TestPackAndHash_RequiresReaderAt rejects outputs that cannot be hashed in place.
func TestPackAndHash_RequiresReaderAt(t *testing.T) {
	t.Parallel()

	out := &memWriteSeeker{}
	inputs := []Input{
		{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("abc"))), nil
			},
			SizeHint: 3,
		},
	}

	_, _, err := PackAndHash(context.Background(), out, inputs, PackOptions{}, SignVersionV3, GameTypeDayZ)
	if !errors.Is(err, ErrReaderAtRequired) {
		t.Fatalf("expected ErrReaderAtRequired, got %v", err)
	}
}

type memWriteSeeker struct {
	buf []byte
	off int64
}

func (m *memWriteSeeker) Write(p []byte) (int, error) {
	if m.off < 0 {
		return 0, ErrSizeOverflow
	}

	end := m.off + int64(len(p))
	if end > int64(len(m.buf)) {
		next := make([]byte, end)
		copy(next, m.buf)
		m.buf = next
	}

	copy(m.buf[m.off:end], p)
	m.off = end

	return len(p), nil
}

func (m *memWriteSeeker) Seek(offset int64, whence int) (int64, error) {
	var next int64
	switch whence {
	case io.SeekStart:
		next = offset
	case io.SeekCurrent:
		next = m.off + offset
	case io.SeekEnd:
		next = int64(len(m.buf)) + offset
	default:
		return 0, errors.New("invalid whence")
	}

	if next < 0 {
		return 0, ErrSizeOverflow
	}

	m.off = next
	return m.off, nil
}

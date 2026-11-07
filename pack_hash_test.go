package pbo

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // PBO trailer format requires SHA1.
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPackAndHash_ReturnsPreTrailerHashes(t *testing.T) {
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

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("stat packed file: %v", err)
			}

			packed := make([]byte, info.Size())
			if _, err := f.ReadAt(packed, 0); err != nil {
				t.Fatalf("read packed file: %v", err)
			}
			if got := sha1.Sum(packed); !bytes.Equal(hsPack.Hash1[:], got[:]) {
				t.Fatalf("PackAndHash hash1=%x, want pre-trailer hash %x", hsPack.Hash1, got)
			}
			if _, err := ComputeHashSet(
				outPath, SignVersionV3, gameType,
			); !errors.Is(err, ErrTrailerTooShort) {
				t.Fatalf("ComputeHashSet() error=%v, want ErrTrailerTooShort for Pack output", err)
			}

			trailer := append([]byte{0}, hsPack.Hash1[:]...)
			if _, err := f.WriteAt(trailer, info.Size()); err != nil {
				t.Fatalf("append trailer: %v", err)
			}
			if err := f.Sync(); err != nil {
				t.Fatalf("sync trailer: %v", err)
			}

			hsFile, err := ComputeHashSet(outPath, SignVersionV3, gameType)
			if err != nil {
				t.Fatalf("ComputeHashSet after trailer: %v", err)
			}
			if hsPack != hsFile {
				t.Fatalf("hash mismatch after trailer:\nPackAndHash=%x\nComputeHashSet=%x", hsPack, hsFile)
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

// TestPackWithoutTrailerRemainsValidButCannotBeSigned checks the Pack contract.
func TestPackWithoutTrailerRemainsValidButCannotBeSigned(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "plain.pbo")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}

	input := []Input{{
		Path: "payload.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("payload"))), nil
		},
		SizeHint: int64(len("payload")),
	}}
	if _, err := Pack(context.Background(), f, input, PackOptions{}); err != nil {
		_ = f.Close()
		t.Fatalf("Pack: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close output: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open packed PBO: %v", err)
	}
	if _, ok := r.SHA1Trailer(); ok {
		_ = r.Close()
		t.Fatal("Pack output unexpectedly has a SHA1 trailer")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}
	if _, err := ComputeHashSet(
		path, SignVersionV3, GameTypeDayZ,
	); !errors.Is(err, ErrTrailerTooShort) {
		t.Fatalf("ComputeHashSet() error=%v, want ErrTrailerTooShort", err)
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

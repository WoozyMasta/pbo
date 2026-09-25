package pbo

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Trailer format requires SHA1.
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// checkSHA1TrailerForTest verifies that the file ends with a valid SHA1 trailer and that
// the stored hash matches the content.
func checkSHA1TrailerForTest(path string) ([20]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [20]byte{}, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return [20]byte{}, fmt.Errorf("seek: %w", err)
	}

	if size < 21 {
		return [20]byte{}, ErrTrailerTooShort
	}

	tail := make([]byte, 21)
	if _, err := f.ReadAt(tail, size-21); err != nil {
		return [20]byte{}, fmt.Errorf("read trailer: %w", err)
	}
	if tail[0] != 0x00 {
		return [20]byte{}, ErrInvalidTrailerPrefix
	}

	var stored [20]byte
	copy(stored[:], tail[1:21])

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return [20]byte{}, err
	}

	h := sha1.New() //nolint:gosec // Trailer format requires SHA1.
	if _, err := io.Copy(h, io.LimitReader(f, size-21)); err != nil {
		return [20]byte{}, fmt.Errorf("hash content: %w", err)
	}
	computed := h.Sum(nil)
	if len(computed) != 20 {
		return [20]byte{}, fmt.Errorf("%w: %d", ErrInvalidSHA1DigestLength, len(computed))
	}
	if !bytes.Equal(stored[:], computed) {
		return [20]byte{}, ErrTrailerHashMismatch
	}

	return stored, nil
}

func TestTrailerDetection_ZeroByteInNoTrailerPayload(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "no-trailer.pbo")
	payload := make([]byte, 21)
	if _, err := PackFile(context.Background(), path, []Input{{
		Path: "zero.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}}, PackOptions{}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("stat: %v", err)
	}
	bodySize := info.Size() - 21
	if err := file.Truncate(bodySize); err != nil {
		_ = file.Close()
		t.Fatalf("truncate trailer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if body[len(body)-21] != 0 {
		t.Fatalf("test fixture byte at size-21 = %#x, want 0", body[len(body)-21])
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if _, ok := r.SHA1Trailer(); ok {
		t.Fatal("SHA1Trailer() reported a trailer for payload data")
	}

	hashSet, err := computeHashSetFromReader(r, SignVersionV2, GameTypeArma)
	if err != nil {
		t.Fatalf("computeHashSetFromReader: %v", err)
	}
	want := sha1.Sum(body) //nolint:gosec // Test mirrors PBO trailer hashing.
	if !bytes.Equal(hashSet.Hash1[:], want[:]) {
		t.Fatalf("hash1 = %x, want full-file hash %x", hashSet.Hash1, want)
	}
}

func TestTrailerDetection_InvalidDigestHashesWholeFile(t *testing.T) {
	t.Parallel()

	path := createMinimalPBO(t)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		t.Fatalf("stat: %v", err)
	}
	if _, err := file.WriteAt([]byte{0x7f}, info.Size()-1); err != nil {
		_ = file.Close()
		t.Fatalf("corrupt trailer digest: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if _, ok := r.SHA1Trailer(); ok {
		t.Fatal("SHA1Trailer() accepted an invalid digest")
	}

	hashSet, err := computeHashSetFromReader(r, SignVersionV2, GameTypeArma)
	if err != nil {
		t.Fatalf("computeHashSetFromReader: %v", err)
	}
	want := sha1.Sum(data) //nolint:gosec // Test mirrors PBO trailer hashing.
	if !bytes.Equal(hashSet.Hash1[:], want[:]) {
		t.Fatalf("hash1 = %x, want full-file hash %x", hashSet.Hash1, want)
	}
}

func TestOpen_TrailerDetectionDoesNotHashPayload(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "large-payload.pbo")
	payload := make([]byte, 4<<20)
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
	counted := &byteCountingReaderAt{reader: bytes.NewReader(data)}
	r, err := NewReaderFromReaderAt(counted, int64(len(data)))
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	_ = r.Close()
	t.Logf("reader consumed %d of %d archive bytes during Open", counted.bytesRead, len(data))
	if counted.bytesRead >= int64(len(data))/2 {
		t.Fatalf("Open read %d bytes from a %d-byte PBO; trailer detection must not hash payload", counted.bytesRead, len(data))
	}
}

func TestReadHeaders_SealedDoesNotReadPayload(t *testing.T) {
	t.Parallel()

	const payloadSize = 4 << 20
	payload := bytes.Repeat([]byte{0x5a}, payloadSize)
	input := []Input{{
		Path: "payload.bin",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}}
	packOpts := PackOptions{Headers: []HeaderPair{{Key: PropertyPrefix, Value: "test\\mod"}}}
	plainPath := filepath.Join(t.TempDir(), "plain-headers.pbo")
	if _, err := PackFile(context.Background(), plainPath, input, packOpts); err != nil {
		t.Fatalf("PackFile plain: %v", err)
	}
	key := sealedTestKey()
	sealedOpts := packOpts
	sealedOpts.SealedKey = &key
	sealedPath := filepath.Join(t.TempDir(), "sealed-headers.pbo")
	if _, err := PackFile(context.Background(), sealedPath, input, sealedOpts); err != nil {
		t.Fatalf("PackFile sealed: %v", err)
	}

	plainData, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("ReadFile plain: %v", err)
	}
	sealedData, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("ReadFile sealed: %v", err)
	}
	plainHeaders, err := ReadHeadersFromReaderAt(bytes.NewReader(plainData), int64(len(plainData)))
	if err != nil {
		t.Fatalf("ReadHeaders plain: %v", err)
	}
	counted := &byteCountingReaderAt{reader: bytes.NewReader(sealedData)}
	sealedHeaders, err := ReadHeadersFromReaderAtWithOptions(counted, int64(len(sealedData)), ReaderOptions{SealedKey: &key})
	if err != nil {
		t.Fatalf("ReadHeaders sealed: %v", err)
	}
	if !equalHeaderPairs(plainHeaders, sealedHeaders) {
		t.Fatalf("sealed headers = %#v, want plain headers %#v", sealedHeaders, plainHeaders)
	}
	t.Logf("sealed header read consumed %d of %d archive bytes", counted.bytesRead, len(sealedData))
	if counted.bytesRead >= int64(payloadSize)/2 {
		t.Fatalf("sealed header read consumed %d bytes for a %d-byte payload", counted.bytesRead, payloadSize)
	}
}

// byteCountingReaderAt records total bytes read by ReaderAt calls.
type byteCountingReaderAt struct {
	// reader is the underlying random-access source.
	reader io.ReaderAt
	// bytesRead is the cumulative number of returned bytes.
	bytesRead int64
}

// ReadAt delegates the read and records its successful byte count.
func (r *byteCountingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.reader.ReadAt(p, off)
	r.bytesRead += int64(n)
	return n, err
}

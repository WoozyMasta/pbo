package pbo

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // Trailer format requires SHA1.
	"fmt"
	"io"
	"os"
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

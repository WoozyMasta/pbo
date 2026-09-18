// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import "errors"

// Sentinel errors for PBO operations. Use errors.Is in callers.
var (
	// ErrInvalidHeader means the PBO file is missing or has a bad header.
	ErrInvalidHeader = errors.New("invalid PBO file: missing or bad header")
	// ErrInvalidHeaderProperty means a header property cannot be represented on the wire.
	ErrInvalidHeaderProperty = errors.New("invalid PBO header property")
	// ErrFileNameTooLong means the entry filename exceeds the maximum length.
	ErrFileNameTooLong = errors.New("entry filename exceeds maximum length")
	// ErrNilReader means the reader is nil.
	ErrNilReader = errors.New("reader is nil")
	// ErrReaderAtRequired means operation requires io.ReaderAt support.
	ErrReaderAtRequired = errors.New("readerAt is required")
	// ErrWriterAtRequired means operation requires io.WriterAt support.
	ErrWriterAtRequired = errors.New("writerAt is required")
	// ErrNilWriter means the writer is nil.
	ErrNilWriter = errors.New("writer is nil")
	// ErrOutputNotEmpty means a non-truncatable output already contains data.
	ErrOutputNotEmpty = errors.New("output is not empty and cannot be truncated")
	// ErrOutputPosition means a non-truncatable output is not positioned at offset zero.
	ErrOutputPosition = errors.New("output is not positioned at offset zero")
	// ErrInvalidOutputTarget means the file output path names a directory.
	ErrInvalidOutputTarget = errors.New("invalid file output target")
	// ErrEntryNotFound means the entry is not found.
	ErrEntryNotFound = errors.New("entry not found")
	// ErrClosed means the reader or resource is already closed.
	ErrClosed = errors.New("reader or resource already closed")
	// ErrSizeOverflow means the size exceeds the uint32 or 4 GiB PBO limit.
	ErrSizeOverflow = errors.New("size exceeds uint32 or 4 GiB PBO limit")
	// ErrEmptyInputs means no inputs provided for pack.
	ErrEmptyInputs = errors.New("no inputs provided for pack")
	// ErrInvalidCompressPattern means one or more compression rules are invalid.
	ErrInvalidCompressPattern = errors.New("invalid compress rules")
	// ErrUnsupportedSignVersion means the signature version is not supported.
	ErrUnsupportedSignVersion = errors.New("unsupported signature version")
	// ErrUnsupportedGameTypeV3 means the game type is not supported for v3.
	ErrUnsupportedGameTypeV3 = errors.New("unsupported game type for v3")
	// ErrTrailerTooShort means the file is too short for the trailer.
	ErrTrailerTooShort = errors.New("file too short for trailer")
	// ErrInvalidTrailerPrefix means the trailer does not start with 0x00.
	ErrInvalidTrailerPrefix = errors.New("trailer does not start with 0x00")
	// ErrTrailerHashMismatch means the trailer hash mismatch.
	ErrTrailerHashMismatch = errors.New("trailer hash mismatch")
	// ErrInvalidSHA1DigestLength means the SHA1 digest length is invalid.
	ErrInvalidSHA1DigestLength = errors.New("invalid SHA1 digest length")
	// ErrInvalidEntryPath means one of input entry paths is empty or invalid after normalization.
	ErrInvalidEntryPath = errors.New("invalid entry path")
	// ErrDuplicateEntryPath means two inputs resolve to the same path (case-insensitive).
	ErrDuplicateEntryPath = errors.New("duplicate entry path")
	// ErrAmbiguousEntryPath means a path operation matches multiple archive entries.
	ErrAmbiguousEntryPath = errors.New("ambiguous entry path")
	// ErrInvalidExtractPath means archive entry path is invalid for extraction destination.
	ErrInvalidExtractPath = errors.New("invalid extract path")
	// ErrExtractPathOutsideRoot means resolved extraction path escapes destination root.
	ErrExtractPathOutsideRoot = errors.New("extract path escapes destination root")
	// ErrInvalidEntryOffset means one or more entry offsets are malformed for selected reader policy.
	ErrInvalidEntryOffset = errors.New("invalid entry offset")
	// ErrReaderLimitExceeded means parser input exceeds a configured resource limit.
	ErrReaderLimitExceeded = errors.New("reader limit exceeded")
)

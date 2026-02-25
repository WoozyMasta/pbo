// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"io"
	"os"
)

// ReadHeaders opens a PBO and returns only header key-value pairs without parsing entry table.
func ReadHeaders(path string) ([]HeaderPair, error) {
	f, size, err := openFileWithSize(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return ReadHeadersFromReaderAt(f, size)
}

// ReadHeadersFromReaderAt reads only PBO header key-value pairs from a random-access source.
func ReadHeadersFromReaderAt(ra io.ReaderAt, size int64) ([]HeaderPair, error) {
	if ra == nil {
		return nil, ErrNilReader
	}
	if size < headerSize {
		return nil, fmt.Errorf("%w: short header", ErrInvalidHeader)
	}

	_, headers, _, err := parseHeaderSection(ra)
	if err != nil {
		return nil, err
	}

	out := make([]HeaderPair, len(headers))
	for i := range headers {
		out[i] = HeaderPair{
			Key:   headers[i].Key,
			Value: headers[i].Value,
		}
	}

	return out, nil
}

// ListEntries opens a PBO and returns entry metadata without payload reads.
func ListEntries(path string) ([]EntryInfo, error) {
	return ListEntriesWithOptions(path, ReaderOptions{})
}

// ListEntriesWithOptions opens a PBO and returns entry metadata without payload reads using reader options.
func ListEntriesWithOptions(path string, opts ReaderOptions) ([]EntryInfo, error) {
	f, size, err := openFileWithSize(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return ListEntriesFromReaderAtWithOptions(f, size, opts)
}

// ListEntriesFromReaderAt parses entry metadata from a random-access source.
func ListEntriesFromReaderAt(ra io.ReaderAt, size int64) ([]EntryInfo, error) {
	return ListEntriesFromReaderAtWithOptions(ra, size, ReaderOptions{})
}

// ListEntriesFromReaderAtWithOptions parses entry metadata from a random-access source using reader options.
func ListEntriesFromReaderAtWithOptions(ra io.ReaderAt, size int64, opts ReaderOptions) ([]EntryInfo, error) {
	opts.applyDefaults()

	if ra == nil {
		return nil, ErrNilReader
	}
	if size < headerSize {
		return nil, fmt.Errorf("%w: short header", ErrInvalidHeader)
	}

	_, _, tableOffset, err := parseHeaderSection(ra)
	if err != nil {
		return nil, err
	}

	r := &Reader{}
	entriesEnd, err := r.parseEntriesBuffered(ra, tableOffset, size)
	if err != nil {
		return nil, err
	}

	if err := resolveEntryOffsets(r.entries, entriesEnd, size, opts.OffsetMode); err != nil {
		return nil, err
	}
	if opts.EnableJunkFilter {
		r.entries = filterJunkEntries(r.entries)
	}
	r.entries = filterEntriesBySize(r.entries, opts.MinEntryOriginalSize, opts.MinEntryDataSize)
	if opts.FilterASCIIOnly {
		r.entries = filterEntriesByASCIIOnly(r.entries)
	}
	if opts.SanitizeNames {
		r.entries = filterEntriesBySanitizedPrefix(r.entries, opts.EntryPathPrefix)
	} else {
		r.entries = filterEntriesByPrefix(r.entries, opts.EntryPathPrefix)
	}
	if opts.SanitizeControlChars {
		r.entries, err = sanitizeEntryInfoControlPaths(r.entries)
		if err != nil {
			return nil, err
		}
	}

	entries := r.entries
	if opts.SanitizeNames {
		entries, err = sanitizeEntryInfoPaths(entries)
		if err != nil {
			return nil, err
		}

		return entries, nil
	}

	return entries, nil
}

// openFileWithSize opens a file and returns a handle plus current size.
func openFileWithSize(path string) (*os.File, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open PBO: %w", err)
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat: %w", err)
	}

	return f, fi.Size(), nil
}

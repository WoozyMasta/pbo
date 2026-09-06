// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// PropertyPrefix names the PBO prefix property.
	PropertyPrefix = "prefix"
	// PropertyVersion names the PBO version property.
	PropertyVersion = "version"
	// PropertyFSShadowing names the PBO filesystem shadowing property.
	PropertyFSShadowing = "fsShadowing"
)

// propertyKeyEqual compares property keys using exact ASCII case-insensitive matching.
func propertyKeyEqual(left string, right string) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		leftChar := left[i]
		rightChar := right[i]
		if leftChar >= 'A' && leftChar <= 'Z' {
			leftChar += 'a' - 'A'
		}
		if rightChar >= 'A' && rightChar <= 'Z' {
			rightChar += 'a' - 'A'
		}
		if leftChar != rightChar {
			return false
		}
	}

	return true
}

// propertyValue returns the first value whose key matches the requested property name.
func propertyValue(headers []HeaderPair, name string) (string, bool) {
	for _, header := range headers {
		if propertyKeyEqual(header.Key, name) {
			return header.Value, true
		}
	}

	return "", false
}

// setProperty replaces matching properties with one value and preserves its first position.
func setProperty(headers []HeaderPair, name string, value string) []HeaderPair {
	updated := make([]HeaderPair, 0, len(headers)+1)
	found := false
	for _, header := range headers {
		if !propertyKeyEqual(header.Key, name) {
			updated = append(updated, header)
			continue
		}
		if found {
			continue
		}

		header.Value = value
		updated = append(updated, header)
		found = true
	}
	if !found {
		updated = append(updated, HeaderPair{Key: name, Value: value})
	}

	return updated
}

// deleteProperty removes all properties whose key matches the requested name.
func deleteProperty(headers []HeaderPair, name string) []HeaderPair {
	for _, header := range headers {
		if propertyKeyEqual(header.Key, name) {
			updated := make([]HeaderPair, 0, len(headers)-1)
			for _, candidate := range headers {
				if !propertyKeyEqual(candidate.Key, name) {
					updated = append(updated, candidate)
				}
			}

			return updated
		}
	}

	return headers
}

// Property returns the first matching named property without trimming its key or value.
func (r *Reader) Property(name string) (string, bool) {
	if r == nil {
		return "", false
	}

	for _, header := range r.headers {
		if propertyKeyEqual(header.Key, name) {
			return header.Value, true
		}
	}

	return "", false
}

// Prefix returns the raw value of the PBO prefix property when present.
func (r *Reader) Prefix() (string, bool) {
	return r.Property(PropertyPrefix)
}

// Version returns the raw value of the PBO version property when present.
func (r *Reader) Version() (string, bool) {
	return r.Property(PropertyVersion)
}

// FSShadowing reports whether the filesystem shadowing property is set to "1".
func (r *Reader) FSShadowing() bool {
	value, ok := r.Property(PropertyFSShadowing)

	return ok && value == "1"
}

// SetProperty sets one named property and removes case-insensitive duplicates.
func (opts *PackOptions) SetProperty(name string, value string) {
	if opts == nil {
		return
	}

	opts.Headers = setProperty(opts.Headers, name, value)
}

// DeleteProperty removes every property whose key matches name.
func (opts *PackOptions) DeleteProperty(name string) {
	if opts == nil {
		return
	}

	opts.Headers = deleteProperty(opts.Headers, name)
}

// SetPrefix stores a normalized PBO prefix property.
func (opts *PackOptions) SetPrefix(value string) {
	opts.SetProperty(PropertyPrefix, NormalizePrefixHeader(value))
}

// SetVersion stores an opaque PBO version property value.
func (opts *PackOptions) SetVersion(value string) {
	opts.SetProperty(PropertyVersion, value)
}

// SetFSShadowing enables the PBO filesystem shadowing property or removes it.
func (opts *PackOptions) SetFSShadowing(enabled bool) {
	if enabled {
		opts.SetProperty(PropertyFSShadowing, "1")
		return
	}

	opts.DeleteProperty(PropertyFSShadowing)
}

// validateHeaderProperties rejects property values that cannot be NUL-terminated safely.
func validateHeaderProperties(headers []HeaderPair) error {
	for i, header := range headers {
		if header.Key == "" || strings.IndexByte(header.Key, 0) >= 0 || strings.IndexByte(header.Value, 0) >= 0 {
			return fmt.Errorf("%w: property %d has an empty key or NUL byte", ErrInvalidHeaderProperty, i)
		}
	}

	return nil
}

// ReadHeaders opens a PBO and returns only header key-value pairs without parsing entry table.
func ReadHeaders(path string) ([]HeaderPair, error) {
	return ReadHeadersWithOptions(path, ReaderOptions{})
}

// ReadHeadersWithOptions opens a PBO and returns only header key-value pairs using reader options.
func ReadHeadersWithOptions(path string, opts ReaderOptions) ([]HeaderPair, error) {
	f, size, err := openFileWithSize(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return ReadHeadersFromReaderAtWithOptions(f, size, opts)
}

// ReadHeadersFromReaderAt reads only PBO header key-value pairs from a random-access source.
func ReadHeadersFromReaderAt(ra io.ReaderAt, size int64) ([]HeaderPair, error) {
	return ReadHeadersFromReaderAtWithOptions(ra, size, ReaderOptions{})
}

// ReadHeadersFromReaderAtWithOptions reads only PBO header key-value pairs from a random-access source.
func ReadHeadersFromReaderAtWithOptions(ra io.ReaderAt, size int64, opts ReaderOptions) ([]HeaderPair, error) {
	opts.applyDefaults()

	if ra == nil {
		return nil, ErrNilReader
	}
	if size < headerSize {
		return nil, fmt.Errorf("%w: short header", ErrInvalidHeader)
	}

	readerAt, err := prepareReaderAtWithSealedOptions(ra, size, opts.SealedKey, opts.TrailerMode, opts.Limits)
	if err != nil {
		return nil, err
	}

	_, headers, _, err := parseHeaderSection(readerAt, size, opts.Limits)
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

	readerAt, err := prepareReaderAtWithSealedOptions(ra, size, opts.SealedKey, opts.TrailerMode, opts.Limits)
	if err != nil {
		return nil, err
	}

	parsed, err := parseRawMetadata(readerAt, size, opts.Limits)
	if err != nil {
		return nil, err
	}
	if err := resolveEntryOffsets(parsed.entries, parsed.dataStart, size, opts.OffsetMode); err != nil {
		return nil, err
	}

	return parsed.entries, nil
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

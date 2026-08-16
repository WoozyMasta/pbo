// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"fmt"
	"io"

	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pathrules"
)

// compressMatcher holds compiled allow-list rules for compression.
type compressMatcher struct {
	matcher *pathrules.Matcher
}

// byteChunksReader reads retained candidate chunks as one continuous byte stream.
type byteChunksReader struct {
	// chunks are source segments retained within the candidate memory limit.
	chunks [][]byte
	// chunkIndex identifies the next source segment.
	chunkIndex int
	// chunkOffset is the next unread byte within the current segment.
	chunkOffset int
}

// Read fills p across chunk boundaries to preserve the stream shape of a contiguous source.
func (r *byteChunksReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	total := 0
	for len(p) > 0 && r.chunkIndex < len(r.chunks) {
		chunk := r.chunks[r.chunkIndex]
		if r.chunkOffset >= len(chunk) {
			r.chunkIndex++
			r.chunkOffset = 0
			continue
		}

		n := copy(p, chunk[r.chunkOffset:])
		total += n
		p = p[n:]
		r.chunkOffset += n
	}
	if total > 0 {
		return total, nil
	}

	return 0, io.EOF
}

// newCompressMatcher compiles compression path rules.
func newCompressMatcher(rules []pathrules.Rule, opts pathrules.MatcherOptions) (*compressMatcher, error) {
	rules = normalizeCompressRules(rules)
	if len(rules) == 0 {
		return nil, nil
	}

	matcher, err := pathrules.NewMatcher(rules, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: compile rules: %w", ErrInvalidCompressPattern, err)
	}

	return &compressMatcher{matcher: matcher}, nil
}

// normalizeCompressRules normalizes rule patterns and drops empty patterns.
func normalizeCompressRules(rules []pathrules.Rule) []pathrules.Rule {
	normalized := make([]pathrules.Rule, 0, len(rules))
	for _, rule := range rules {
		pattern := normalizePathForMatching(rule.Pattern)
		if pattern == "" {
			continue
		}

		normalized = append(normalized, pathrules.Rule{
			Action:  rule.Action,
			Pattern: pattern,
		})
	}

	return normalized
}

// Match reports whether path is included by at least one compress rule.
func (m *compressMatcher) Match(path string) bool {
	if m == nil || m.matcher == nil {
		return false
	}

	candidate := NormalizePath(path)
	if candidate == "" {
		return false
	}

	return m.matcher.Included(candidate, false)
}

// shouldCompress returns true if path and size pass compression policy.
func shouldCompress(opts PackOptions, matcher *compressMatcher, path string, size uint32) bool {
	if !shouldCompressBySize(opts, size) {
		return false
	}

	if matcher == nil {
		return false
	}

	return matcher.Match(path)
}

// shouldCompressBySize reports whether payload size fits compression boundaries.
func shouldCompressBySize(opts PackOptions, size uint32) bool {
	if size > opts.MaxCompressSize || size < opts.MinCompressSize {
		return false
	}

	return true
}

// compressLZSS compresses the data using LZSS.
func compressLZSS(data []byte) ([]byte, error) {
	return lzss.Compress(data, lzss.DefaultCompressOptions())
}

// compressLZSSReader compresses a stream into memory without combining input chunks first.
func compressLZSSReader(src io.Reader) ([]byte, error) {
	var compressed bytes.Buffer
	if _, _, err := lzss.CompressToWriter(&compressed, src, nil); err != nil {
		return nil, err
	}

	return compressed.Bytes(), nil
}

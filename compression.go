// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"fmt"

	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pathrules"
)

// compressMatcher holds compiled allow-list rules for compression.
type compressMatcher struct {
	matcher *pathrules.Matcher
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

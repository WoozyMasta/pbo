// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/woozymasta/bimime"
)

const (
	// compressionProfilePrefixSize bounds format detection reads from streaming inputs.
	compressionProfilePrefixSize = 64
)

// compressionSizeBounds narrows the global candidate range for one auto-profile format.
type compressionSizeBounds struct {
	min uint32
	max uint32
}

// compressionSelection carries a classified stream and its format-specific size limits.
type compressionSelection struct {
	source    io.Reader
	bounds    compressionSizeBounds
	candidate bool
}

// selectCompressionInput selects rules or the automatic profile and replays sniffed bytes.
func selectCompressionInput(
	opts PackOptions,
	matcher *compressMatcher,
	in Input,
	src io.Reader,
) (compressionSelection, error) {
	if !shouldUseCompressionForInput(opts, matcher, in) {
		return compressionSelection{source: src}, nil
	}
	if len(opts.CompressRules) > 0 {
		return compressionSelection{candidate: true, source: src}, nil
	}

	if !autoCompressionNeedsPrefix(in.Path) {
		bounds, ok := autoCompressionBounds(in.Path, nil)
		if !ok || !compressionSizeHintMatches(opts, bounds, in.SizeHint) {
			return compressionSelection{source: src}, nil
		}

		return compressionSelection{candidate: true, source: src, bounds: bounds}, nil
	}

	prefixSize := max(compressionProfilePrefixSize, bimime.RequiredPrefix(in.Path, bimime.ProfileThorough))
	prefix := make([]byte, prefixSize)
	n, err := io.ReadFull(src, prefix)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return compressionSelection{}, fmt.Errorf("read compression profile prefix for %s: %w", in.Path, err)
	}

	prefix = prefix[:n]
	bounds, ok := autoCompressionBounds(in.Path, prefix)
	replayed := io.MultiReader(bytes.NewReader(prefix), src)
	if !ok || !compressionSizeHintMatches(opts, bounds, in.SizeHint) {
		return compressionSelection{source: replayed}, nil
	}

	return compressionSelection{candidate: true, source: replayed, bounds: bounds}, nil
}

// autoCompressionNeedsPrefix reports whether the path's profile class needs content inspection.
func autoCompressionNeedsPrefix(entryPath string) bool {
	switch strings.ToLower(path.Ext(NormalizePath(entryPath))) {
	case ".bin", ".bisurf", ".c", ".cfg", ".cpp", ".csv", ".emat", ".fnt", ".hpp",
		".imageset", ".json", ".layout", ".md", ".meta", ".ptc", ".p3d", ".rvmat",
		".styles", ".tga", ".txt", ".xml", ".wrp":
		return true

	default:
		return false
	}
}

// autoCompressionMayApply avoids prefix reads for paths the automatic profile never selects.
func autoCompressionMayApply(entryPath string) bool {
	switch strings.ToLower(path.Ext(NormalizePath(entryPath))) {
	case ".ae", ".agf", ".agr", ".anm", ".asi", ".ast", ".asy", ".aw", ".bisurf",
		".bin", ".c", ".cfg", ".cpp", ".csv", ".emat", ".fnt", ".hpp", ".imageset",
		".json", ".layout", ".map", ".md", ".meta", ".pac", ".paa", ".ptc", ".p3d",
		".ragdoll", ".rvmat", ".seq", ".styles", ".tga", ".txt", ".xml", ".wrp":
		return true

	default:
		return false
	}
}

// autoCompressionBounds returns measured candidate size limits for a format signature.
func autoCompressionBounds(entryPath string, prefix []byte) (compressionSizeBounds, bool) {
	defaultBounds := compressionSizeBounds{min: DefaultMinCompressSize}
	result := bimime.Analyze(entryPath, prefix, bimime.ProfileThorough)

	switch strings.ToLower(path.Ext(NormalizePath(entryPath))) {
	case ".ae", ".agf", ".agr", ".asi", ".ast", ".asy", ".aw", ".ragdoll", ".seq":
		return defaultBounds, result.Type != bimime.UnknownID

	case ".pac":
		return compressionSizeBounds{min: 128, max: 128 << 10}, result.Type == "image.paa"

	case ".paa":
		return compressionSizeBounds{min: 128, max: 16 << 10}, result.Type == "image.paa"

	case ".anm":
		return compressionSizeBounds{min: 128}, result.ByPath == "bi.animation.anm"

	case ".bin":
		isRAPConfig := result.Type == "bi.config.main.bin" && result.ByContent == "bi.rap"
		return defaultBounds, result.ByContent == "bi.texheaders" || isRAPConfig

	case ".bisurf":
		return compressionSizeBounds{min: 128}, isTextCompressionPrefix(prefix)

	case ".md":
		return compressionSizeBounds{min: 128}, isTextCompressionPrefix(prefix)

	case ".map":
		return defaultBounds, result.Type == "bi.world.areaflags-map"

	case ".fnt":
		return defaultBounds, result.Type == "bi.font.fnt" && result.ByContent == "bi.font.fnt"

	case ".tga":
		return defaultBounds, result.Type == "image.tga" && isTGACompressionPrefix(prefix)

	case ".rvmat":
		if result.Type == "bi.rvmat.bin" && result.ByContent == "bi.rap" {
			return defaultBounds, true
		}

		typ, found := bimime.Lookup(result.Type)
		return compressionSizeBounds{min: 128}, found && typ.Has(bimime.TraitText) && isTextCompressionPrefix(prefix)

	case ".c", ".cfg", ".cpp", ".csv", ".emat", ".hpp", ".imageset", ".json",
		".layout", ".meta", ".ptc", ".styles", ".txt", ".xml":
		typ, found := bimime.Lookup(result.Type)
		return compressionSizeBounds{min: 128}, found && typ.Has(bimime.TraitText) && isTextCompressionPrefix(prefix)

	case ".p3d":
		switch result.ByContent {
		case "bi.p3d.mlod":
			return compressionSizeBounds{min: 128}, true

		case "bi.p3d.odol":
			return compressionSizeBounds{min: 128, max: 128 << 10}, true

		default:
			return compressionSizeBounds{}, false
		}

	case ".wrp":
		return defaultBounds, result.ByContent == "bi.wrp.oprw" || result.ByContent == "bi.wrp.8wvr"

	default:
		return compressionSizeBounds{}, false
	}
}

// isTGACompressionPrefix accepts supported TGA headers with valid dimensions and pixel depth.
func isTGACompressionPrefix(prefix []byte) bool {
	if len(prefix) < 18 || prefix[1] > 1 {
		return false
	}

	imageType := prefix[2]
	depth := prefix[16]
	validDepth := false

	switch imageType {
	case 1, 9:
		validDepth = prefix[1] == 1 && (depth == 8 || depth == 16)

	case 2, 10:
		validDepth = prefix[1] == 0 && (depth == 15 || depth == 16 || depth == 24 || depth == 32)

	case 3, 11:
		validDepth = prefix[1] == 0 && (depth == 8 || depth == 16)

	default:
		return false
	}

	if !validDepth {
		return false
	}

	return binary.LittleEndian.Uint16(prefix[12:14]) > 0 &&
		binary.LittleEndian.Uint16(prefix[14:16]) > 0
}

// compressionSizeHintMatches applies profile and caller limits before candidate buffering.
func compressionSizeHintMatches(opts PackOptions, bounds compressionSizeBounds, sizeHint int64) bool {
	if sizeHint <= 0 {
		return true
	}

	if opts.MinCompressSize > bounds.min {
		bounds.min = opts.MinCompressSize
	}
	if sizeHint < int64(bounds.min) || sizeHint > int64(opts.MaxCompressSize) {
		return false
	}

	return bounds.max == 0 || sizeHint <= int64(bounds.max)
}

// isTextCompressionPrefix rejects binary variants of extensions that also hold text.
func isTextCompressionPrefix(prefix []byte) bool {
	if !utf8.Valid(prefix) {
		return false
	}

	for _, b := range prefix {
		if b == 0 || (b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != '\f') {
			return false
		}
	}

	return true
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import "github.com/woozymasta/bimime"

const (
	// DefaultMaxBlankScanBytes is the per-entry payload limit when blank scanning is enabled.
	DefaultMaxBlankScanBytes uint32 = 1024

	// HardMaxBlankScanBytes is the largest allowed per-entry blank scan.
	HardMaxBlankScanBytes uint32 = 64 * 1024 * 1024

	// DefaultMaxContentProbeBytes bounds one BIMIME content probe.
	DefaultMaxContentProbeBytes uint32 = 4096

	// DefaultMaxCompressedScanBytes bounds one packed compressed payload.
	DefaultMaxCompressedScanBytes uint32 = 4096

	// HardMaxCompressedScanBytes is the largest packed payload decoded by one scan.
	HardMaxCompressedScanBytes uint32 = 64 * 1024 * 1024

	// DefaultMaxDecodedScanBytes bounds one decoded compressed payload.
	DefaultMaxDecodedScanBytes uint32 = 1024

	// HardMaxDecodedScanBytes is the largest decoded payload retained by one scan.
	HardMaxDecodedScanBytes uint32 = 64 * 1024 * 1024
)

// Options configures entry selection. Payload filters are disabled unless
// explicitly enabled; all payload reads are bounded per entry.
type Options struct {
	// PathPrefix keeps an exact normalized path or a complete descendant path.
	// Empty disables this filter; non-empty values that normalize to empty are invalid.
	PathPrefix string `json:"path_prefix,omitempty" yaml:"path_prefix,omitempty"`

	// AllowedBinaryTypes lists registered binary BIMIME types retained by SkipDisallowedBinary.
	AllowedBinaryTypes []bimime.TypeID `json:"allowed_binary_types,omitempty" yaml:"allowed_binary_types,omitempty"`

	// MinEstimatedSize is the inclusive lower bound for OriginalSize,
	// falling back to DataSize when OriginalSize is zero.
	MinEstimatedSize uint32 `json:"min_estimated_size,omitempty" yaml:"min_estimated_size,omitempty"`

	// MaxEstimatedSize is the inclusive upper bound for the estimated size.
	MaxEstimatedSize uint32 `json:"max_estimated_size,omitempty" yaml:"max_estimated_size,omitempty"`

	// MinStoredSize is the inclusive lower bound for stored payload bytes.
	MinStoredSize uint32 `json:"min_stored_size,omitempty" yaml:"min_stored_size,omitempty"`

	// MaxStoredSize is the inclusive upper bound for stored payload bytes.
	MaxStoredSize uint32 `json:"max_stored_size,omitempty" yaml:"max_stored_size,omitempty"`

	// MaxBlankScanBytes bounds one uncompressed payload scan. Zero uses the
	// default; values above HardMaxBlankScanBytes are invalid.
	MaxBlankScanBytes uint32 `json:"max_blank_scan_bytes,omitempty" yaml:"max_blank_scan_bytes,omitempty"`

	// MaxContentProbeBytes bounds one stored payload prefix read. Zero uses
	// DefaultMaxContentProbeBytes when ProbeContentType is enabled.
	MaxContentProbeBytes uint32 `json:"max_content_probe_bytes,omitempty" yaml:"max_content_probe_bytes,omitempty"`

	// MaxCompressedScanBytes bounds stored bytes decoded by ScanCompressedSmall.
	// Zero uses the default; values above HardMaxCompressedScanBytes are invalid.
	MaxCompressedScanBytes uint32 `json:"max_compressed_scan_bytes,omitempty" yaml:"max_compressed_scan_bytes,omitempty"`

	// MaxDecodedScanBytes bounds decoded bytes retained by ScanCompressedSmall.
	// Zero uses the default; values above HardMaxDecodedScanBytes are invalid.
	MaxDecodedScanBytes uint32 `json:"max_decoded_scan_bytes,omitempty" yaml:"max_decoded_scan_bytes,omitempty"`

	// ASCIIOnly keeps entries whose raw path bytes are all ASCII.
	ASCIIOnly bool `json:"ascii_only,omitempty" yaml:"ascii_only,omitempty"`

	// SkipEmpty excludes entries with no stored payload bytes.
	SkipEmpty bool `json:"skip_empty,omitempty" yaml:"skip_empty,omitempty"`

	// SkipInvalidPaths excludes paths rejected by pbo extraction validation.
	SkipInvalidPaths bool `json:"skip_invalid_paths,omitempty" yaml:"skip_invalid_paths,omitempty"`

	// SkipBlankOnly excludes small payloads made only of whitespace and comments.
	SkipBlankOnly bool `json:"skip_blank_only,omitempty" yaml:"skip_blank_only,omitempty"`

	// ProbeContentType enables bounded BIMIME content classification.
	ProbeContentType bool `json:"probe_content_type,omitempty" yaml:"probe_content_type,omitempty"`

	// SkipUnknownBinary excludes complete probes confirmed as binary with no content type.
	SkipUnknownBinary bool `json:"skip_unknown_binary,omitempty" yaml:"skip_unknown_binary,omitempty"`

	// SkipDisallowedBinary excludes known binary content types absent from AllowedBinaryTypes.
	SkipDisallowedBinary bool `json:"skip_disallowed_binary,omitempty" yaml:"skip_disallowed_binary,omitempty"`

	// ScanCompressedSmall enables bounded LZSS decoding for small compressed entries.
	ScanCompressedSmall bool `json:"scan_compressed_small,omitempty" yaml:"scan_compressed_small,omitempty"`
}

// ViewOptions configures optional display-path projection.
type ViewOptions struct {
	// FilesystemSafe applies pbo's extraction-compatible sanitation
	// and collision resolution to the selected set.
	FilesystemSafe bool `json:"filesystem_safe,omitempty" yaml:"filesystem_safe,omitempty"`

	// ControlChars replaces control, format, and invalid UTF-8 runes for display.
	ControlChars bool `json:"control_chars,omitempty" yaml:"control_chars,omitempty"`
}

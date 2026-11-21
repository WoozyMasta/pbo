// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import (
	"github.com/woozymasta/bimime"
	"github.com/woozymasta/pbo"
)

// Match identifies one selected physical record and preserves its raw metadata.
type Match struct {
	// DecodeError contains the decoder error when bounded decompression failed.
	DecodeError string `json:"decode_error,omitempty" yaml:"decode_error,omitempty"`

	// ProbeResult contains BIMIME evidence when HasProbeResult is true.
	ProbeResult bimime.Result `json:"probe_result,omitzero" yaml:"probe_result,omitempty"`

	// Raw is the original entry metadata, including its unmodified path.
	Raw pbo.EntryInfo `json:"raw" yaml:"raw"`

	// SourceIndex is the zero-based index in Reader.EntriesView.
	SourceIndex int `json:"source_index" yaml:"source_index"`

	// ConsumedBytes is the packed prefix consumed by a successful LZSS decode.
	ConsumedBytes uint32 `json:"consumed_bytes,omitempty" yaml:"consumed_bytes,omitempty"`

	// HasProbeResult distinguishes an unrun probe from an unknown result.
	HasProbeResult bool `json:"has_probe_result,omitempty" yaml:"has_probe_result,omitempty"`

	// TextLike reports that the bounded prefix appears to be text-like.
	TextLike bool `json:"text_like,omitempty" yaml:"text_like,omitempty"`

	// Decoded reports that compressed payload bytes were successfully decoded.
	Decoded bool `json:"decoded,omitempty" yaml:"decoded,omitempty"`

	// RawFallback reports that packed bytes were classified after a decode error.
	RawFallback bool `json:"raw_fallback,omitempty" yaml:"raw_fallback,omitempty"`
}

// Statistics summarizes one selection pass and its enabled payload checks.
type Statistics struct {
	// Visited is the number of raw index records examined.
	Visited int `json:"visited" yaml:"visited"`

	// Selected is the number of records retained.
	Selected int `json:"selected" yaml:"selected"`

	// Excluded is the number of records rejected by enabled filters.
	Excluded int `json:"excluded" yaml:"excluded"`

	// BlankOnly counts entries excluded by SkipBlankOnly.
	BlankOnly int `json:"blank_only" yaml:"blank_only"`

	// NotBlank counts scanned entries that contain a non-comment token.
	NotBlank int `json:"not_blank" yaml:"not_blank"`

	// NotScannedSize counts uncompressed entries above the per-entry scan limit.
	NotScannedSize int `json:"not_scanned_size" yaml:"not_scanned_size"`

	// NotScannedCompressed counts compressed entries kept without decoded checks.
	NotScannedCompressed int `json:"not_scanned_compressed" yaml:"not_scanned_compressed"`

	// Unknown counts retained entries without a proven content classification,
	// including payloads skipped by a size or compression limit.
	Unknown int `json:"unknown" yaml:"unknown"`

	// Probed counts payload prefixes analyzed by BIMIME.
	Probed int `json:"probed" yaml:"probed"`

	// ByContent counts probes with content evidence.
	ByContent int `json:"by_content" yaml:"by_content"`

	// PathOnly counts probes with path evidence but no content evidence.
	PathOnly int `json:"path_only" yaml:"path_only"`

	// Conflict counts probes where path and content evidence disagree.
	Conflict int `json:"conflict" yaml:"conflict"`

	// Incomplete counts probes whose available prefix was below RequiredPrefix.
	Incomplete int `json:"incomplete" yaml:"incomplete"`

	// UnknownBinary counts entries excluded by SkipUnknownBinary.
	UnknownBinary int `json:"unknown_binary" yaml:"unknown_binary"`

	// DisallowedBinary counts entries excluded by SkipDisallowedBinary.
	DisallowedBinary int `json:"disallowed_binary" yaml:"disallowed_binary"`

	// CompressedCandidates counts entries considered by ScanCompressedSmall.
	CompressedCandidates int `json:"compressed_candidates" yaml:"compressed_candidates"`

	// DecodedSmall counts successful bounded LZSS decodes.
	DecodedSmall int `json:"decoded_small" yaml:"decoded_small"`

	// DecodeFailed counts bounded LZSS decode failures.
	DecodeFailed int `json:"decode_failed" yaml:"decode_failed"`

	// RawFallback counts decode failures classified from packed bytes.
	RawFallback int `json:"raw_fallback" yaml:"raw_fallback"`

	// SkippedSizeBudget counts compressed entries above either configured limit.
	SkippedSizeBudget int `json:"skipped_size_budget" yaml:"skipped_size_budget"`

	// ConsumedLessStored counts successful blocks with trailing stored bytes.
	ConsumedLessStored int `json:"consumed_less_stored" yaml:"consumed_less_stored"`
}

// ViewEntry pairs raw metadata with its display path and parent path.
type ViewEntry struct {
	// DisplayPath is the path projected for listing or display.
	DisplayPath string `json:"display_path" yaml:"display_path"`

	// ParentPath is the slash-separated display parent, empty for root entries.
	ParentPath string `json:"parent_path,omitempty" yaml:"parent_path,omitempty"`

	// Raw is the original entry metadata used for identity and payload access.
	Raw pbo.EntryInfo `json:"raw" yaml:"raw"`

	// SourceIndex is the zero-based index in the original reader.
	SourceIndex int `json:"source_index" yaml:"source_index"`
}

// Selection stores matching entries in source order.
type Selection struct {
	// entries retains selected raw metadata without changing entry identity.
	entries []pbo.EntryInfo
	// sourceIndices maps selected metadata back to the original index.
	sourceIndices []int
	// probeResults stores content diagnostics aligned with entries.
	probeResults []probeDiagnostic
	// statistics summarizes the completed selection pass.
	statistics Statistics
}

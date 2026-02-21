// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"io"
	"time"

	"github.com/woozymasta/pathrules"
)

// Internal binary layout and format limits.
const (
	headerSize = 21      // fixed PBO header size in bytes
	shaSize    = 20      // SHA1 digest size in trailer
	crcSize    = 4       // CRC size in bytes
	maxNameLen = 512     // max entry filename length
	maxPBOData = 1 << 32 // max addressable payload in classic PBO (4 GiB)
)

// Default packer tuning values.
const (
	DefaultWriteBuffer     = 16 * 1024 * 1024
	DefaultMinCompressSize = 512
	DefaultMaxCompressSize = 16 * 1024 * 1024
)

// MimeType is the 4-byte PBO entry type (stored little-endian).
type MimeType uint32

// PBO entry mime constants.
const (
	// MimeHeader marks the first header record ("Vers").
	MimeHeader MimeType = 0x56657273
	// MimeCompress marks LZSS-compressed data ("Cprs").
	MimeCompress MimeType = 0x43707273
	// MimeEncoded marks VBS-encrypted data ("Enco").
	MimeEncoded MimeType = 0x456e6372
	// MimeNil marks uncompressed or terminator entry.
	MimeNil MimeType = 0x00000000
)

// HashSet contains signature hashes for one PBO.
type HashSet struct {
	// Hash1 is SHA1 of the full PBO data (without trailer).
	Hash1 [20]byte `json:"hash1" yaml:"hash1"`
	// Hash2 is composed from hash1, name hash, and prefix rules.
	Hash2 [20]byte `json:"hash2" yaml:"hash2"`
	// Hash3 is composed from file hash, name hash, and prefix rules.
	Hash3 [20]byte `json:"hash3" yaml:"hash3"`
}

// EntryInfo describes a single parsed PBO entry.
type EntryInfo struct {
	// Path is the entry path as stored in archive index.
	Path string `json:"path" yaml:"path"`
	// Offset is byte offset of entry payload.
	Offset uint32 `json:"offset" yaml:"offset"`
	// DataSize is stored payload size in bytes.
	DataSize uint32 `json:"data_size" yaml:"data_size"`
	// OriginalSize is uncompressed size for compressed entries; zero otherwise.
	OriginalSize uint32 `json:"original_size,omitempty" yaml:"original_size,omitempty"`
	// TimeStamp is Unix timestamp from entry record.
	TimeStamp uint32 `json:"timestamp,omitempty" yaml:"timestamp,omitempty"`
	// MimeType stores entry mime marker.
	MimeType MimeType `json:"mime_type,omitempty" yaml:"mime_type,omitempty"`
}

// IsCompressed reports whether this entry is stored with LZSS compression.
func (e *EntryInfo) IsCompressed() bool {
	return e.MimeType == MimeCompress || (e.OriginalSize != 0 && e.DataSize < e.OriginalSize)
}

// Input describes one source stream to be packed into a PBO entry.
type Input struct {
	// ModTime is optional entry timestamp.
	ModTime time.Time `json:"mod_time" yaml:"mod_time"`
	// Open returns raw source stream for this entry.
	Open func() (io.ReadCloser, error) `json:"-" yaml:"-"`
	// Path is destination path inside PBO.
	Path string `json:"path" yaml:"path"`
	// SizeHint is expected size in bytes (zero when unknown).
	SizeHint int64 `json:"size_hint,omitempty" yaml:"size_hint,omitempty"`
}

// HeaderPair is a PBO header key-value pair written in provided order.
type HeaderPair struct {
	Key   string `json:"key" yaml:"key"`
	Value string `json:"value" yaml:"value"`
}

// PackEntryProgress contains one completed entry write event from pack flow.
type PackEntryProgress struct {
	// Path is entry path written to archive.
	Path string `json:"path" yaml:"path"`
	// Offset is payload offset in resulting archive.
	Offset uint32 `json:"offset" yaml:"offset"`
	// DataSize is stored payload size in bytes.
	DataSize uint32 `json:"data_size" yaml:"data_size"`
	// OriginalSize is original size for compressed entries; zero for raw entries.
	OriginalSize uint32 `json:"original_size,omitempty" yaml:"original_size,omitempty"`
	// MimeType is stored entry mime marker.
	MimeType MimeType `json:"mime_type,omitempty" yaml:"mime_type,omitempty"`
	// CompressionCandidate reports whether compression path was selected for this input entry.
	CompressionCandidate bool `json:"compression_candidate,omitempty" yaml:"compression_candidate,omitempty"`
	// Compressed reports whether compressed payload was actually written.
	Compressed bool `json:"compressed,omitempty" yaml:"compressed,omitempty"`
}

// PackOptions configures pack behavior.
type PackOptions struct {
	// OnEntryDone is called after one entry is fully written to archive payload.
	OnEntryDone func(entry PackEntryProgress) `json:"-" yaml:"-"`
	// Headers are written in deterministic order.
	Headers []HeaderPair `json:"headers,omitempty" yaml:"headers,omitempty"`
	// Compress defines ordered path rules for compression candidate selection.
	Compress []pathrules.Rule `json:"compress,omitempty" yaml:"compress,omitempty"`
	// CompressMatcherOptions control compression path rule matching.
	CompressMatcherOptions pathrules.MatcherOptions `json:"compress_matcher_options,omitzero" yaml:"compress_matcher_options,omitzero"`
	// WriterBufferSize is buffered writer size in bytes.
	WriterBufferSize int `json:"writer_buffer_size,omitempty" yaml:"writer_buffer_size,omitempty"`
	// MinCompressSize disables compression for entries smaller than this size.
	// Default is 512 bytes.
	MinCompressSize uint32 `json:"min_compress_size,omitempty" yaml:"min_compress_size,omitempty"`
	// MaxCompressSize disables compression for entries larger than this size.
	// Default is 16 MiB and also bounds known-size in-memory compression path.
	MaxCompressSize uint32 `json:"max_compress_size,omitempty" yaml:"max_compress_size,omitempty"`
}

// PackResult contains pack output statistics.
type PackResult struct {
	// WrittenEntries is number of entries written to archive.
	WrittenEntries int `json:"written_entries" yaml:"written_entries"`
	// DataSize is total payload bytes written.
	DataSize int64 `json:"data_size" yaml:"data_size"`
	// IndexSize is total index bytes written.
	IndexSize int64 `json:"index_size" yaml:"index_size"`
	// RawBytes is total bytes written for uncompressed payload entries.
	RawBytes int64 `json:"raw_bytes,omitempty" yaml:"raw_bytes,omitempty"`
	// CompressedBytes is total bytes written for compressed payload entries.
	CompressedBytes int64 `json:"compressed_bytes,omitempty" yaml:"compressed_bytes,omitempty"`
	// CompressedEntries is number of entries written with compressed payload.
	CompressedEntries int `json:"compressed_entries,omitempty" yaml:"compressed_entries,omitempty"`
	// SkippedCompressionEntries is number of compression candidates stored as raw payload.
	SkippedCompressionEntries int `json:"skipped_compression_entries,omitempty" yaml:"skipped_compression_entries,omitempty"`
	// Duration is end-to-end pack core duration.
	Duration time.Duration `json:"duration,omitempty" yaml:"duration,omitempty"`
}

// EditOptions configures file-based archive edit flow.
type EditOptions struct {
	// PackOptions are applied for added/replaced entries during commit.
	PackOptions PackOptions `json:"pack_options,omitzero" yaml:"pack_options,omitzero"`
	// BackupKeep controls how many backup generations are kept after successful commit.
	// 0 means remove backup, 1 keeps only `<archive>.bak`, N keeps `.bak` + `.bak.1..N-1`.
	BackupKeep int `json:"backup_keep,omitempty" yaml:"backup_keep,omitempty"`
}

// OffsetMode controls how reader resolves payload offsets from index table.
type OffsetMode string

// Reader offset resolution modes.
const (
	// OffsetModeSequential ignores stored index offsets and derives payload offsets sequentially.
	OffsetModeSequential OffsetMode = "sequential"
	// OffsetModeStoredCompat tries to use non-zero stored offsets and falls back to sequential on malformed data.
	OffsetModeStoredCompat OffsetMode = "stored_compat"
	// OffsetModeStoredStrict requires stored non-zero offsets to be valid and fails otherwise.
	OffsetModeStoredStrict OffsetMode = "stored_strict"
)

// ReaderOptions configures reader parse compatibility behavior.
type ReaderOptions struct {
	// OffsetMode controls whether stored index offsets are used.
	OffsetMode OffsetMode `json:"offset_mode,omitempty" yaml:"offset_mode,omitempty"`
	// EnableJunkFilter drops malformed/mangled entries from visible entry list.
	EnableJunkFilter bool `json:"enable_junk_filter,omitempty" yaml:"enable_junk_filter,omitempty"`
	// SanitizeNames rewrites entry paths to filesystem-safe names for listing workflows.
	SanitizeNames bool `json:"sanitize_names,omitempty" yaml:"sanitize_names,omitempty"`
}

// ExtractOptions configures Extract behavior.
type ExtractOptions struct {
	// OnEntryDone is called after one entry is fully written to disk.
	OnEntryDone func(entry EntryInfo, written int64, outputPath string) `json:"-" yaml:"-"`
	// FileMode controls output file creation policy.
	FileMode ExtractFileMode `json:"file_mode,omitempty" yaml:"file_mode,omitempty"`
	// Entries limits extraction to selected metadata list; nil means all parsed entries.
	Entries []EntryInfo `json:"-" yaml:"-"`
	// MaxWorkers is number of extraction workers (zero means GOMAXPROCS).
	MaxWorkers int `json:"max_workers,omitempty" yaml:"max_workers,omitempty"`
	// RawNames disables default path sanitization during extract.
	// When false (default), extract rewrites names to filesystem-safe output paths.
	RawNames bool `json:"raw_names,omitempty" yaml:"raw_names,omitempty"`
}

// ExtractFileMode controls output file open behavior during extraction.
type ExtractFileMode string

// Output file creation policies for extraction.
const (
	// ExtractFileModeAuto first tries create-only, then falls back to truncate for existing files.
	ExtractFileModeAuto ExtractFileMode = "auto"
	// ExtractFileModeOverwriteSmart rewrites files in place and truncates only when existing file is larger.
	ExtractFileModeOverwriteSmart ExtractFileMode = "overwrite_smart"
	// ExtractFileModeTruncate opens existing files with truncate and creates missing files.
	ExtractFileModeTruncate ExtractFileMode = "truncate"
	// ExtractFileModeCreateOnly creates files only when absent and fails on existing files.
	ExtractFileModeCreateOnly ExtractFileMode = "create_only"
)

// applyDefaults fills zero-valued pack options with defaults.
func (opts *PackOptions) applyDefaults() {
	if opts.WriterBufferSize < 4096 {
		opts.WriterBufferSize = DefaultWriteBuffer
	}

	if opts.MinCompressSize == 0 {
		opts.MinCompressSize = DefaultMinCompressSize
	}

	if opts.MaxCompressSize == 0 || opts.MaxCompressSize <= opts.MinCompressSize {
		opts.MaxCompressSize = DefaultMaxCompressSize
	}

	if opts.CompressMatcherOptions == (pathrules.MatcherOptions{}) {
		opts.CompressMatcherOptions = pathrules.MatcherOptions{
			CaseInsensitive: true,
			DefaultAction:   pathrules.ActionExclude,
		}
	}

	if opts.CompressMatcherOptions.DefaultAction == pathrules.ActionUnknown {
		opts.CompressMatcherOptions.DefaultAction = pathrules.ActionExclude
	}
}

// applyDefaults fills zero-valued reader options with defaults.
func (opts *ReaderOptions) applyDefaults() {
	if opts.OffsetMode == "" {
		opts.OffsetMode = OffsetModeSequential
	}
}

// applyDefaults fills zero-valued edit options with defaults.
func (opts *EditOptions) applyDefaults() {
	opts.PackOptions.applyDefaults()

	if opts.BackupKeep < 0 {
		opts.BackupKeep = 0
	}
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import (
	"context"
	"fmt"
	"io"

	"github.com/woozymasta/bimime"
	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pbo"
)

// selectionScanner carries reusable buffers and counters through one Select pass.
type selectionScanner struct {
	ctx               context.Context // ctx allows cancellation between entry scans.
	reader            *pbo.Reader     // reader supplies packed and decoded entry streams.
	prefix            string          // prefix is the normalized, case-folded path filter.
	prefixWithSlash   string          // prefixWithSlash matches descendants at a path boundary.
	blankBuffer       []byte          // blankBuffer reuses storage for complete blank scans.
	probeBuffer       []byte          // probeBuffer reuses storage for bounded content probes.
	packedBuffer      []byte          // packedBuffer reuses storage for bounded compressed entries.
	decodedBuffer     []byte          // decodedBuffer reuses storage for bounded decompressed entries.
	opts              Options         // opts contains validated filter settings.
	selection         Selection       // selection accumulates matches and statistics.
	maxBlankScanBytes uint32          // maxBlankScanBytes is the effective per-entry blank scan limit.
}

// Select applies metadata filters before enabled bounded payload checks.
func Select(ctx context.Context, reader *pbo.Reader, opts Options) (Selection, error) {
	if reader == nil {
		return Selection{}, pbo.ErrNilReader
	}
	if ctx == nil {
		return Selection{}, ErrNilContext
	}

	select {
	case <-ctx.Done():
		return Selection{}, ctx.Err()
	default:
	}

	// Reject invalid policy combinations before touching archive payloads.
	prefix, prefixWithSlash, maxBlankScanBytes, err := validateOptions(opts)
	if err != nil {
		return Selection{}, err
	}

	// Visited counts the full index, including records rejected by metadata filters.
	entries := reader.EntriesView()
	scanner := selectionScanner{
		ctx:               ctx,
		reader:            reader,
		opts:              opts,
		selection:         Selection{statistics: Statistics{Visited: len(entries)}},
		maxBlankScanBytes: maxBlankScanBytes,
		prefix:            prefix,
		prefixWithSlash:   prefixWithSlash,
	}

	for index, entry := range entries {
		// Poll between records so cancellation stops large scans without returning a partial selection.
		select {
		case <-ctx.Done():
			return Selection{}, ctx.Err()
		default:
		}

		// Discard records using index metadata first; these checks cannot prove payload content,
		// but they can avoid all I/O for entries outside the requested path or size range.
		if !scanner.passesMetadataFilters(entry) {
			continue
		}

		if err := scanner.processEntry(index, entry); err != nil {
			return Selection{}, err
		}
	}

	scanner.selection.statistics.Selected = len(scanner.selection.entries)
	scanner.selection.statistics.Excluded = scanner.selection.statistics.Visited - scanner.selection.statistics.Selected

	return scanner.selection, nil
}

// validateOptions checks filter combinations and resolves zero-value defaults.
func validateOptions(opts Options) (string, string, uint32, error) {
	// Contradictory ranges cannot match any entry, so fail instead of silently returning none.
	if opts.MinEstimatedSize > 0 &&
		opts.MaxEstimatedSize > 0 &&
		opts.MinEstimatedSize > opts.MaxEstimatedSize {
		return "", "", 0, fmt.Errorf("%w: minimum estimated size exceeds maximum", ErrInvalidOptions)
	}
	if opts.MinStoredSize > 0 &&
		opts.MaxStoredSize > 0 &&
		opts.MinStoredSize > opts.MaxStoredSize {
		return "", "", 0, fmt.Errorf("%w: minimum stored size exceeds maximum", ErrInvalidOptions)
	}

	// Hard caps protect this library from accidental unbounded allocations even when callers tune defaults.
	if opts.MaxBlankScanBytes > HardMaxBlankScanBytes {
		return "", "", 0, fmt.Errorf("%w: blank scan limit exceeds hard cap", ErrInvalidOptions)
	}
	if opts.MaxCompressedScanBytes > HardMaxCompressedScanBytes ||
		opts.MaxDecodedScanBytes > HardMaxDecodedScanBytes {
		return "", "", 0, fmt.Errorf("%w: compressed scan limits exceed hard caps", ErrInvalidOptions)
	}

	// Binary exclusion needs an actual content probe;
	// path guesses or an unprobed entry are not enough evidence
	// to classify something as disposable binary data.
	if (opts.SkipUnknownBinary || opts.SkipDisallowedBinary) &&
		!opts.ProbeContentType {
		return "", "", 0, fmt.Errorf("%w: binary filters require content probing", ErrInvalidOptions)
	}
	if opts.SkipDisallowedBinary && len(opts.AllowedBinaryTypes) == 0 {
		return "", "", 0, fmt.Errorf("%w: SkipDisallowedBinary requires AllowedBinaryTypes", ErrInvalidOptions)
	}
	if !opts.SkipDisallowedBinary && len(opts.AllowedBinaryTypes) > 0 {
		// A supplied allowlist is otherwise inert and could mislead callers into assuming it is enforced.
		return "", "", 0, fmt.Errorf("%w: AllowedBinaryTypes requires SkipDisallowedBinary", ErrInvalidOptions)
	}

	for _, typeID := range opts.AllowedBinaryTypes {
		typ, ok := bimime.Lookup(typeID)
		// A whitelist containing unknown or non-binary IDs would make the exclusion policy ambiguous.
		if !ok || !typ.Has(bimime.TraitBinary) {
			return "", "", 0, fmt.Errorf("%w: allowed type %q is not a registered binary type", ErrInvalidOptions, typeID)
		}
	}

	// Normalize only the comparison key; selected records retain their raw archive paths.
	normalizedPrefix := pbo.NormalizePath(opts.PathPrefix)
	if opts.PathPrefix != "" && normalizedPrefix == "" {
		// Do not silently turn an invalid non-empty filter into "match everything".
		return "", "", 0, fmt.Errorf("%w: path prefix normalizes to empty", ErrInvalidOptions)
	}

	maxBlankScanBytes := opts.MaxBlankScanBytes
	if maxBlankScanBytes == 0 {
		// Preserve the conservative per-entry read ceiling for zero-value Options.
		maxBlankScanBytes = DefaultMaxBlankScanBytes
	}

	prefix := asciiLower(normalizedPrefix)
	return prefix, prefix + "/", maxBlankScanBytes, nil
}

// passesMetadataFilters rejects records using index metadata only.
func (s *selectionScanner) passesMetadataFilters(entry pbo.EntryInfo) bool {
	// These checks use index metadata only; payload-based rules run later and may retain Unknown.
	if s.opts.SkipEmpty && entry.DataSize == 0 {
		// This explicit size policy checks stored bytes;
		// it does not infer anything from the path or content.
		return false
	}
	if s.opts.SkipInvalidPaths && pbo.ValidateExtractPath(entry.Path) != nil {
		// Unsafe paths are excluded only when requested;
		// otherwise raw archive identity must be preserved.
		return false
	}

	if s.opts.MinEstimatedSize > 0 || s.opts.MaxEstimatedSize > 0 {
		// OriginalSize is the logical size for compressed entries;
		// zero means the stored size is all we know.
		estimatedSize := entry.OriginalSize
		if estimatedSize == 0 {
			estimatedSize = entry.DataSize
		}
		if s.opts.MinEstimatedSize > 0 && estimatedSize < s.opts.MinEstimatedSize {
			return false
		}
		if s.opts.MaxEstimatedSize > 0 && estimatedSize > s.opts.MaxEstimatedSize {
			return false
		}
	}

	if s.opts.MinStoredSize > 0 && entry.DataSize < s.opts.MinStoredSize {
		return false
	}
	if s.opts.MaxStoredSize > 0 && entry.DataSize > s.opts.MaxStoredSize {
		return false
	}

	if s.opts.ASCIIOnly && !isASCII(entry.Path) {
		// This option filters suspicious raw names, not file contents;
		// Unicode is never rewritten here.
		return false
	}

	if s.prefix != "" && !pathHasPrefix(entry.Path, s.prefix, s.prefixWithSlash) {
		return false
	}

	return true
}

// processEntry runs payload checks in order and appends the record if retained.
func (s *selectionScanner) processEntry(index int, entry pbo.EntryInfo) error {
	compressed := entry.IsCompressed()
	var knownPrefix []byte
	diagnostic := probeDiagnostic{}
	// Blank scanning and content probing can both report uncertainty for one entry; count it once.
	unknownRecorded := false

	if compressed {
		// Blank and content scans need decoded script bytes, never the LZSS control stream.
		var done bool
		var err error
		knownPrefix, diagnostic, done, err = s.scanCompressed(index, entry)
		if err != nil || done {
			// scanCompressed appends entries it handled early (disabled, over budget, or decode failure).
			return err
		}
	}

	if s.opts.SkipBlankOnly {
		// A proven comment-only result can be discarded; incomplete or undecodable data stays selected.
		var excluded bool
		var err error
		knownPrefix, unknownRecorded, excluded, err = s.scanBlank(entry, compressed, knownPrefix, unknownRecorded)
		if err != nil || excluded {
			return err
		}
	}

	if s.opts.ProbeContentType {
		var err error
		diagnostic, _, err = s.probe(entry, compressed, knownPrefix, diagnostic, unknownRecorded)
		if err != nil {
			return err
		}
		if s.skipBinaryMatch(compressed, diagnostic) {
			return nil
		}
	}

	s.selection.appendEntry(index, entry, diagnostic)
	return nil
}

// scanCompressed decodes eligible packed entries and retains raw fallbacks on decode errors.
func (s *selectionScanner) scanCompressed(
	index int,
	entry pbo.EntryInfo,
) ([]byte, probeDiagnostic, bool, error) {
	diagnostic := probeDiagnostic{}
	if !s.opts.ScanCompressedSmall {
		// Packed bytes are not source text; without opt-in decoding, keep the entry as Unknown.
		if s.opts.SkipBlankOnly || s.opts.ProbeContentType {
			s.selection.statistics.NotScannedCompressed++
			s.selection.statistics.Unknown++
		}
		s.selection.appendEntry(index, entry, diagnostic)

		return nil, diagnostic, true, nil
	}

	s.selection.statistics.CompressedCandidates++

	maxPackedBytes := s.opts.MaxCompressedScanBytes
	if maxPackedBytes == 0 {
		maxPackedBytes = DefaultMaxCompressedScanBytes
	}

	maxDecodedBytes := s.opts.MaxDecodedScanBytes
	if maxDecodedBytes == 0 {
		maxDecodedBytes = DefaultMaxDecodedScanBytes
	}

	// Check both sizes before reading or allocating:
	// the packed cap limits I/O, while the declared output cap limits memory
	// even when a tiny input expands substantially.
	if entry.DataSize > maxPackedBytes || entry.OriginalSize > maxDecodedBytes {
		s.selection.statistics.SkippedSizeBudget++
		s.selection.statistics.NotScannedCompressed++
		s.selection.statistics.Unknown++
		s.selection.appendEntry(index, entry, diagnostic)
		return nil, diagnostic, true, nil
	}

	// Read the full bounded block because the decoder may need bytes beyond the content-probe prefix.
	var err error
	s.packedBuffer, err = readPackedPayload(s.reader, entry, s.packedBuffer)
	if err != nil {
		return nil, diagnostic, false, fmt.Errorf("read compressed payload for %q: %w", entry.Path, err)
	}

	decodedSize64 := int64(entry.OriginalSize)
	if decodedSize64 > int64(^uint(0)>>1) {
		// Guard the int conversion independently from caller limits so this remains safe on 32-bit builds.
		return nil, diagnostic, false, fmt.Errorf(
			"decode compressed payload for %q: output size exceeds platform limit",
			entry.Path,
		)
	}

	decodedSize := int(decodedSize64)
	// Reuse capacity across entries, but expose only the declared output length to the decoder.
	if cap(s.decodedBuffer) < decodedSize {
		s.decodedBuffer = make([]byte, decodedSize)
	}
	s.decodedBuffer = s.decodedBuffer[:decodedSize]
	consumed, decodeErr := lzss.DecompressInto(s.decodedBuffer, s.packedBuffer, nil)

	if decodeErr != nil {
		// A bad compression marker or damaged stream does not prove the entry is junk.
		return s.retainRawFallback(index, entry, decodeErr)
	}

	if consumed < 0 || uint64(consumed) > uint64(entry.DataSize) {
		// A decoder count outside the packed block cannot be reported or safely narrowed to the archive field type.
		return nil, diagnostic, false, fmt.Errorf(
			"decode compressed payload for %q: invalid consumed byte count %d",
			entry.Path, consumed,
		)
	}

	diagnostic.decoded = true
	// Trailing packed bytes are tolerated and counted;
	// decoding success only claims the declared output,
	// while consumers must finish with this reusable buffer before the next entry.
	// #nosec G115 // consumed was checked against the uint32 packed size.
	diagnostic.consumed = uint32(consumed)
	s.selection.statistics.DecodedSmall++
	if uint64(consumed) < uint64(entry.DataSize) {
		s.selection.statistics.ConsumedLessStored++
	}

	return s.decodedBuffer, diagnostic, false, nil
}

// retainRawFallback records a decode failure and probes packed bytes only when requested.
func (s *selectionScanner) retainRawFallback(
	index int,
	entry pbo.EntryInfo,
	decodeErr error,
) ([]byte, probeDiagnostic, bool, error) {
	s.selection.statistics.DecodeFailed++
	s.selection.statistics.RawFallback++
	s.selection.statistics.Unknown++
	diagnostic := probeDiagnostic{
		rawFallback: true,
		decodeError: decodeErr.Error(),
	}
	rawPrefix := s.packedBuffer

	// On failure, inspect only the same bounded prefix used by normal probes;
	// never promote this fallback to a content-based exclusion
	// because it is still compressed/invalid data.
	probeLimit := s.opts.MaxContentProbeBytes
	if probeLimit == 0 {
		probeLimit = DefaultMaxContentProbeBytes
	}
	if uint64(len(rawPrefix)) > uint64(probeLimit) {
		rawPrefix = rawPrefix[:probeLimit]
	}

	diagnostic.textLike, _ = classifyTextLike(rawPrefix)

	if s.opts.ProbeContentType {
		diagnostic = analyzeContentPrefix(entry.Path, rawPrefix, probeLimit)
		diagnostic.rawFallback = true
		diagnostic.decodeError = decodeErr.Error()
		s.selection.recordProbe(diagnostic)
	}

	s.selection.appendEntry(index, entry, diagnostic)
	return nil, diagnostic, true, nil
}

// scanBlank classifies eligible bytes as blank, non-blank, or unknown.
func (s *selectionScanner) scanBlank(
	entry pbo.EntryInfo,
	compressed bool,
	knownPrefix []byte,
	unknownRecorded bool,
) ([]byte, bool, bool, error) {
	scanData := knownPrefix
	// Compressed entries reach this stage only after a successful bounded decode.
	scanAvailable := compressed

	switch {
	case compressed && uint64(len(scanData)) > uint64(s.maxBlankScanBytes):
		// The decoded output exceeded the blank-scan ceiling;
		// do not classify a prefix as wholly blank.
		s.selection.statistics.NotScannedSize++
		s.recordUnknown(unknownRecorded)
		unknownRecorded = true
		scanAvailable = false
		scanData = nil

	case !compressed && entry.DataSize > s.maxBlankScanBytes:
		// A partial read cannot prove that the rest of the file contains only comments.
		s.selection.statistics.NotScannedSize++
		s.recordUnknown(unknownRecorded)
		unknownRecorded = true

	case !compressed:
		// Blank detection must see the complete payload, otherwise a later code token could be missed.
		var err error
		scanData, err = readBlankPayload(s.reader, entry, s.blankBuffer)
		if err != nil {
			return nil, unknownRecorded, false, fmt.Errorf("scan blank content for %q: %w", entry.Path, err)
		}

		s.blankBuffer = scanData
		knownPrefix = scanData
		scanAvailable = true
	}

	if scanAvailable {
		switch scanBlankOnly(scanData) {
		case blankScanOnly:
			// Only a complete, positively recognized whitespace/comment scan is safe to discard.
			s.selection.statistics.BlankOnly++
			return knownPrefix, unknownRecorded, true, nil

		case blankScanHasContent:
			// A real token is enough to keep the entry, even if the path or extension looks suspicious.
			s.selection.statistics.NotBlank++

		case blankScanUnknown:
			// Malformed encoding, binary controls, or unterminated comments are uncertainty, not proof of junk.
			s.recordUnknown(unknownRecorded)
			unknownRecorded = true
		}
	}

	return knownPrefix, unknownRecorded, false, nil
}

// recordUnknown avoids counting an entry twice when another scan already marked it unknown.
func (s *selectionScanner) recordUnknown(unknownRecorded bool) {
	if !unknownRecorded {
		s.selection.statistics.Unknown++
	}
}

// probe classifies available bytes and updates unknown-probe accounting.
func (s *selectionScanner) probe(
	entry pbo.EntryInfo,
	compressed bool,
	knownPrefix []byte,
	decodeDiagnostic probeDiagnostic,
	unknownRecorded bool,
) (probeDiagnostic, bool, error) {
	maxProbeBytes := s.opts.MaxContentProbeBytes
	if maxProbeBytes == 0 {
		maxProbeBytes = DefaultMaxContentProbeBytes
	}

	var diagnostic probeDiagnostic
	if compressed {
		// Classify the decoded script bytes already in memory;
		// rereading the packed stream would classify the compression format instead of the file content.
		diagnostic = analyzeContentPrefix(entry.Path, knownPrefix, maxProbeBytes)
		diagnostic.decoded = true
		diagnostic.consumed = decodeDiagnostic.consumed
	} else {
		// A prior blank scan may already have read the whole payload;
		// pass it through to avoid a second I/O pass.
		var err error
		diagnostic, s.probeBuffer, err = probeEntry(
			s.reader, entry, s.probeBuffer, maxProbeBytes, knownPrefix,
		)
		if err != nil {
			return probeDiagnostic{}, unknownRecorded, fmt.Errorf("probe content for %q: %w", entry.Path, err)
		}
	}

	s.selection.recordProbe(diagnostic)
	if !hasContentEvidence(diagnostic.result.ByContent) && !unknownRecorded {
		// A path match or incomplete probe is not enough to prove the file's content type.
		s.selection.statistics.Unknown++
		unknownRecorded = true
	}

	return diagnostic, unknownRecorded, nil
}

// skipBinaryMatch applies binary-only filters after the probe has established complete evidence.
func (s *selectionScanner) skipBinaryMatch(compressed bool, diagnostic probeDiagnostic) bool {
	if compressed && !diagnostic.decoded {
		// Failed/disabled decompression provides no evidence about the original binary content.
		return false
	}

	if s.opts.SkipUnknownBinary && diagnostic.complete && diagnostic.binary &&
		!hasContentEvidence(diagnostic.result.ByContent) {
		// Exclude only a complete probe with binary controls and no recognized content type.
		s.selection.statistics.UnknownBinary++
		return true
	}

	if !s.opts.SkipDisallowedBinary || !diagnostic.complete ||
		!hasContentEvidence(diagnostic.result.ByContent) {
		// Incomplete or unrecognized evidence cannot establish that a known type is disallowed.
		return false
	}

	typ, ok := bimime.Lookup(diagnostic.result.ByContent)
	if ok && typ.Has(bimime.TraitBinary) &&
		!containsType(s.opts.AllowedBinaryTypes, diagnostic.result.ByContent) {
		// This policy targets known binary payloads only;
		// text and unregistered types remain selected.
		s.selection.statistics.DisallowedBinary++
		return true
	}

	return false
}

// appendEntry stores one raw record and its original source index.
func (s *Selection) appendEntry(sourceIndex int, entry pbo.EntryInfo, diagnostic probeDiagnostic) {
	s.entries = append(s.entries, entry)
	s.sourceIndices = append(s.sourceIndices, sourceIndex)
	s.probeResults = append(s.probeResults, diagnostic)
}

// readBlankPayload fills a reusable buffer and verifies the full stored payload was read.
func readBlankPayload(reader *pbo.Reader, entry pbo.EntryInfo, buffer []byte) ([]byte, error) {
	needed := int(entry.DataSize)
	// The caller enforces the per-entry ceiling before this allocation;
	// reuse capacity across scans.
	if cap(buffer) < needed {
		buffer = make([]byte, needed)
	}
	buffer = buffer[:needed]

	stream, err := reader.OpenEntryInfo(entry)
	if err != nil {
		return nil, err
	}

	read, readErr := io.ReadFull(stream, buffer)
	closeErr := stream.Close()
	if readErr != nil {
		// A short read cannot prove the unseen tail is comment-only, so propagate it instead of excluding.
		return nil, readErr
	}
	if read != needed {
		return nil, io.ErrUnexpectedEOF
	}
	if closeErr != nil {
		// Do not return a successful classification if the underlying entry stream failed to close cleanly.
		return nil, closeErr
	}

	return buffer, nil
}

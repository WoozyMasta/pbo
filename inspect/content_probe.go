// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import (
	"fmt"
	"io"
	"slices"
	"unicode"
	"unicode/utf8"

	"github.com/woozymasta/bimime"
	"github.com/woozymasta/pbo"
)

// probeDiagnostic retains bounded classification and text evidence for a match.
type probeDiagnostic struct {
	decodeError string        // decodeError stores the bounded decoder's diagnostic message.
	result      bimime.Result // result is BIMIME's path/content classification.
	consumed    uint32        // consumed is the packed byte count consumed by successful decoding.
	probed      bool          // probed distinguishes an unrun probe from an unknown result.
	complete    bool          // complete reports that the planned BIMIME prefix was available.
	textLike    bool          // textLike reports valid UTF-8 without binary control bytes.
	binary      bool          // binary reports strong control-byte evidence in valid UTF-8.
	decoded     bool          // decoded reports that the prefix came from successful LZSS decoding.
	rawFallback bool          // rawFallback reports that packed bytes were inspected after decode failure.
}

// probeEntry reads one bounded stored prefix and classifies it without decoding.
func probeEntry(
	reader *pbo.Reader,
	entry pbo.EntryInfo,
	buffer []byte,
	limit uint32,
	knownPrefix []byte,
) (probeDiagnostic, []byte, error) {
	required := bimime.RequiredPrefix(entry.Path, bimime.ProfileThorough)
	if required < 0 {
		return probeDiagnostic{}, buffer, fmt.Errorf("bimime returned negative prefix requirement %d", required)
	}

	// Read only the prefix BIMIME can use, further bounded by caller policy and stored size.
	// maxInt also keeps the later int conversion safe on 32-bit builds if BIMIME asks for a large prefix.
	maxInt := int64(^uint(0) >> 1)
	readSize := min(int64(required), int64(limit), int64(entry.DataSize), maxInt)
	readLength := int(readSize)

	if len(knownPrefix) >= readLength {
		// Blank scanning or decompression already supplied enough bytes, so no second stream is needed.
		buffer = knownPrefix[:readLength]
	} else {
		if cap(buffer) < readLength {
			buffer = make([]byte, readLength)
		}
		buffer = buffer[:readLength]
	}

	if len(knownPrefix) < readLength && len(buffer) > 0 {
		// Read packed bytes directly so probing never applies decompression or content transformations.
		stream, err := reader.OpenPackedEntryInfo(entry)
		if err != nil {
			return probeDiagnostic{}, buffer, err
		}

		_, readErr := io.ReadFull(stream, buffer)
		closeErr := stream.Close()
		if readErr != nil {
			// Incomplete evidence must reach Select as an error, not look like a valid unknown probe.
			return probeDiagnostic{}, buffer, readErr
		}
		if closeErr != nil {
			return probeDiagnostic{}, buffer, closeErr
		}
	}

	diagnostic := analyzeContentPrefix(entry.Path, buffer, limit)
	diagnostic.probed = true
	return diagnostic, buffer, nil
}

// readPackedPayload reads one complete stored entry into a bounded reusable buffer.
func readPackedPayload(reader *pbo.Reader, entry pbo.EntryInfo, buffer []byte) ([]byte, error) {
	maxInt := int64(^uint(0) >> 1)
	if int64(entry.DataSize) > maxInt {
		// Convert to int only after checking the current platform can represent the full stored entry.
		return nil, fmt.Errorf("packed size %d exceeds platform limit", entry.DataSize)
	}

	needed := int(entry.DataSize)
	// The caller has already enforced per-entry input/output budgets;
	// retain capacity for the next candidate.
	if cap(buffer) < needed {
		buffer = make([]byte, needed)
	}

	buffer = buffer[:needed]
	if needed == 0 {
		// Empty packed blocks need no stream,
		// but still return a usable empty slice to the decoder.
		return buffer, nil
	}

	stream, err := reader.OpenPackedEntryInfo(entry)
	if err != nil {
		return nil, err
	}

	_, readErr := io.ReadFull(stream, buffer)
	closeErr := stream.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	return buffer, nil
}

// analyzeContentPrefix classifies a caller-owned prefix without performing I/O.
func analyzeContentPrefix(name string, data []byte, limit uint32) probeDiagnostic {
	required := bimime.RequiredPrefix(name, bimime.ProfileThorough)
	prefix := data
	if required >= 0 && len(prefix) > required {
		// BIMIME's extension-specific requirement avoids analyzing irrelevant trailing bytes.
		prefix = prefix[:required]
	}
	if uint64(len(prefix)) > uint64(limit) {
		// Keep caller policy authoritative even when a reusable input buffer is larger.
		prefix = prefix[:limit]
	}

	result := bimime.Analyze(name, prefix, bimime.ProfileThorough)
	textLike, binary := classifyTextLike(prefix)

	return probeDiagnostic{
		result:   result,
		probed:   true,
		complete: !result.Has(bimime.FlagIncomplete),
		textLike: textLike,
		binary:   binary,
	}
}

// classifyTextLike distinguishes readable text from strong binary controls.
func classifyTextLike(prefix []byte) (bool, bool) {
	if !utf8.Valid(prefix) {
		// Invalid UTF-8 is neither evidence of readable text nor sufficient evidence for binary exclusion.
		return false, false
	}

	for _, current := range string(prefix) {
		if current == '\t' || current == '\n' || current == '\r' || current == '\f' {
			continue
		}

		if unicode.IsControl(current) {
			// A valid text encoding with unexpected controls is strong evidence of binary content.
			return false, true
		}
	}

	// Empty input is valid UTF-8 but provides no positive evidence that the file is text.
	return len(prefix) > 0, false
}

// containsType reports whether types includes id.
func containsType(types []bimime.TypeID, id bimime.TypeID) bool {
	return slices.Contains(types, id)
}

// hasContentEvidence reports whether BIMIME produced a content type.
func hasContentEvidence(id bimime.TypeID) bool {
	return id != "" && id != bimime.UnknownID
}

// recordProbe adds classification evidence to aggregate counters.
func (s *Selection) recordProbe(diagnostic probeDiagnostic) {
	s.statistics.Probed++
	if hasContentEvidence(diagnostic.result.ByContent) {
		// Content evidence takes precedence over path-only matching in the aggregate counters.
		s.statistics.ByContent++
	}
	if diagnostic.result.ByPath != "" && !hasContentEvidence(diagnostic.result.ByContent) {
		// Record path-only matches separately; they do not prove the bytes match the extension.
		s.statistics.PathOnly++
	}
	if diagnostic.result.Relation == bimime.RelationConflict {
		s.statistics.Conflict++
	}
	if diagnostic.result.Has(bimime.FlagIncomplete) {
		s.statistics.Incomplete++
	}
}

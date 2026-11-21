// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import "unicode/utf8"

// blankScanResult describes whether a bounded payload is blank, contains a token, or is unknown.
type blankScanResult uint8

const (
	blankScanUnknown blankScanResult = iota
	blankScanOnly
	blankScanHasContent
)

// scanBlankOnly checks one payload for ASCII whitespace and C-style comments.
func scanBlankOnly(data []byte) blankScanResult {
	// The scanner recognizes ASCII source syntax only;
	// other UTF encodings cannot be safely interpreted byte-by-byte
	// and therefore must not be called comment-only.
	if hasUTF16Or32BOM(data) {
		return blankScanUnknown
	}

	position := 0
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		// UTF-8 BOM is a known optional prefix, so skip it before scanning source tokens.
		position = 3
	}

	for position < len(data) {
		current := data[position]
		switch current {
		case ' ', '\t', '\r', '\n':
			position++

		case '/':
			if position+1 >= len(data) {
				// A final slash is a token, not a complete comment opener.
				return blankScanHasContent
			}

			switch data[position+1] {
			case '/':
				// Consume through the line ending; comment markers inside the comment have no syntax.
				position += 2
				for position < len(data) {
					current = data[position]
					if current == '\r' || current == '\n' {
						position++
						break
					}

					width, unknown := scanCommentRune(data[position:])
					if unknown {
						return blankScanUnknown
					}

					position += width
				}

			case '*':
				// A block comment is ignorable only if its closing delimiter is present in this payload.
				position += 2
				closed := false
				for position < len(data) {
					if data[position] == '*' && position+1 < len(data) && data[position+1] == '/' {
						position += 2
						closed = true
						break
					}

					width, unknown := scanCommentRune(data[position:])
					if unknown {
						return blankScanUnknown
					}

					position += width
				}

				if !closed {
					// Treat truncation as unknown instead of dropping a possibly incomplete script.
					return blankScanUnknown
				}

			default:
				// A slash not followed by a comment opener is ordinary content.
				return blankScanHasContent
			}

		default:
			if isBinaryControlByte(current) || isInvalidUTF8Lead(data[position:]) {
				// Binary or malformed text is not safe to classify as disposable comments.
				return blankScanUnknown
			}

			// Any valid non-whitespace token proves this entry is not blank-only.
			return blankScanHasContent
		}
	}

	return blankScanOnly
}

// hasUTF16Or32BOM reports byte-order marks whose encoding is not scanned.
func hasUTF16Or32BOM(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// UTF-16 BOMs are enough to reject byte-oriented scanning before inspecting later bytes.
	if data[0] == 0xff && data[1] == 0xfe || data[0] == 0xfe && data[1] == 0xff {
		return true
	}

	return len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
		data[2] == 0xfe && data[3] == 0xff
}

// isBinaryControlByte rejects controls that are not recognized ASCII whitespace.
func isBinaryControlByte(value byte) bool {
	// Tabs and line endings are valid text whitespace; other C0/DEL controls suggest binary data.
	return value < 0x20 && value != '\t' && value != '\r' && value != '\n' || value == 0x7f
}

// isInvalidUTF8Lead reports an invalid UTF-8 byte at the start of a text token.
func isInvalidUTF8Lead(data []byte) bool {
	if len(data) == 0 || data[0] < utf8.RuneSelf {
		return false
	}

	_, width := utf8.DecodeRune(data)
	return width == 1
}

// scanCommentRune validates one comment byte or UTF-8 rune and rejects binary controls.
func scanCommentRune(data []byte) (int, bool) {
	current := data[0]
	if isBinaryControlByte(current) {
		return 1, true
	}

	if current < utf8.RuneSelf {
		return 1, false
	}

	// Validate multibyte text even inside comments; invalid bytes must not be hidden by comment stripping.
	_, width := utf8.DecodeRune(data)
	return width, width == 1
}

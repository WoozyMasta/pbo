// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import (
	"bytes"
	"testing"
)

func TestScanBlankOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want blankScanResult
	}{
		{name: "empty", want: blankScanOnly},
		{name: "whitespace", data: []byte(" \t\r\n"), want: blankScanOnly},
		{name: "line comment at eof", data: []byte("// comment"), want: blankScanOnly},
		{name: "line comment crlf", data: []byte("// comment\r\n  // next\n"), want: blankScanOnly},
		{name: "block comment", data: []byte("/* comment */"), want: blankScanOnly},
		{name: "mixed comments", data: []byte(" \n/* first */ // second\r\n"), want: blankScanOnly},
		{name: "utf8 bom", data: []byte{0xef, 0xbb, 0xbf, '/', '/', 'x'}, want: blankScanOnly},
		{name: "code after comment", data: []byte("/* comment */\n#include \"x.paa\""), want: blankScanHasContent},
		{name: "code last byte", data: append(bytes.Repeat([]byte{' '}, 1023), 'x'), want: blankScanHasContent},
		{name: "single slash", data: []byte("/"), want: blankScanHasContent},
		{name: "slash token", data: []byte("/x"), want: blankScanHasContent},
		{name: "semicolon", data: []byte(";"), want: blankScanHasContent},
		{name: "unclosed block", data: []byte("/* comment"), want: blankScanUnknown},
		{name: "nul token", data: []byte{0}, want: blankScanUnknown},
		{name: "nul in comment", data: []byte{'/', '/', 'x', 0}, want: blankScanUnknown},
		{name: "binary control in block", data: []byte{'/', '*', 0x01, '*', '/'}, want: blankScanUnknown},
		{name: "utf16 bom", data: []byte{0xff, 0xfe, ' ', 0}, want: blankScanUnknown},
		{name: "utf32 bom", data: []byte{0, 0, 0xfe, 0xff}, want: blankScanUnknown},
		{name: "invalid utf8 in comment", data: []byte{'/', '/', 0xff}, want: blankScanUnknown},
		{name: "invalid utf8 token", data: []byte{0xff}, want: blankScanUnknown},
		{name: "vertical tab is not whitespace", data: []byte{0x0b}, want: blankScanUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := scanBlankOnly(test.data); got != test.want {
				t.Fatalf("scanBlankOnly(%q) = %d, want %d", test.data, got, test.want)
			}
		})
	}
}

func FuzzScanBlankOnly(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte(" \t\r\n"),
		[]byte("// comment"),
		[]byte("/* comment */"),
		[]byte("/* unclosed"),
		{0, 0xff, '/', '*'},
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first := scanBlankOnly(data)
		if first > blankScanHasContent {
			t.Fatalf("unexpected scanner result %d", first)
		}
		if second := scanBlankOnly(data); first != second {
			t.Fatalf("scanner is not deterministic: first=%d second=%d", first, second)
		}
	})
}

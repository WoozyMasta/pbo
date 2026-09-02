// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackOptionsProperties_RoundTrip(t *testing.T) {
	t.Parallel()

	opts := PackOptions{Headers: []HeaderPair{
		{Key: "PREFIX", Value: "old"},
		{Key: "prefix", Value: "duplicate"},
		{Key: "custom", Value: "preserved"},
		{Key: "CUSTOM", Value: "second raw value"},
		{Key: "version", Value: "old"},
		{Key: "fsShadowing", Value: "0"},
	}}
	opts.SetPrefix("test/mod")
	opts.SetVersion("")
	opts.SetFSShadowing(true)
	opts.SetProperty("unknown", "opaque")

	path := filepath.Join(t.TempDir(), "properties.pbo")
	if _, err := PackFile(context.Background(), path, []Input{{
		Path: "entry.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("data"))), nil
		},
	}}, opts); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got, ok := r.Prefix(); !ok || got != `test\mod` {
		t.Fatalf("Prefix() = %q, %v; want %q, true", got, ok, `test\mod`)
	}
	if got, ok := r.Version(); !ok || got != "" {
		t.Fatalf("Version() = %q, %v; want empty, true", got, ok)
	}
	if !r.FSShadowing() {
		t.Fatal("FSShadowing() = false, want true")
	}
	if got, ok := r.Property("UNKNOWN"); !ok || got != "opaque" {
		t.Fatalf("Property(UNKNOWN) = %q, %v; want opaque, true", got, ok)
	}
	if got, ok := r.Property("custom"); !ok || got != "preserved" {
		t.Fatalf("Property(custom) = %q, %v; want preserved, true", got, ok)
	}
	if _, ok := r.Property("missing"); ok {
		t.Fatal("Property(missing) unexpectedly found a value")
	}

	headers := r.Headers()
	if len(headers) != 6 {
		t.Fatalf("Headers() returned %d pairs, want 6: %#v", len(headers), headers)
	}
	if headers[0].Key != "PREFIX" || headers[0].Value != `test\mod` {
		t.Fatalf("first header = %#v, want original key casing and normalized value", headers[0])
	}
	if headers[1] != (HeaderPair{Key: "custom", Value: "preserved"}) ||
		headers[2] != (HeaderPair{Key: "CUSTOM", Value: "second raw value"}) {
		t.Fatalf("unknown duplicate properties lost their raw order: %#v", headers[:3])
	}

	opts.SetFSShadowing(false)
	if _, ok := propertyValue(opts.Headers, PropertyFSShadowing); ok {
		t.Fatal("SetFSShadowing(false) did not remove the property")
	}
	disabledPath := filepath.Join(t.TempDir(), "properties-disabled.pbo")
	if _, err := PackFile(context.Background(), disabledPath, []Input{{
		Path: "entry.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("data"))), nil
		},
	}}, opts); err != nil {
		t.Fatalf("PackFile after disabling fsShadowing: %v", err)
	}
	disabled, err := Open(disabledPath)
	if err != nil {
		t.Fatalf("Open disabled properties: %v", err)
	}
	defer func() { _ = disabled.Close() }()
	if disabled.FSShadowing() {
		t.Fatal("FSShadowing() = true after disabling the property")
	}
}

func TestPropertyKeyEqual_UsesExactASCIIComparison(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		left  string
		right string
		want  bool
	}{
		{left: "PREFIX", right: "prefix", want: true},
		{left: " prefix ", right: "prefix", want: false},
		{left: "Key", right: "key", want: false},
	}
	for _, tc := range testCases {
		if got := propertyKeyEqual(tc.left, tc.right); got != tc.want {
			t.Errorf("propertyKeyEqual(%q, %q) = %v, want %v", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestPack_RawWhitespacePropertyKeyIsNotNormalized(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "raw-property.pbo")
	if _, err := PackFile(context.Background(), path, []Input{{
		Path: "entry.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("payload")), nil
		},
	}}, PackOptions{Headers: []HeaderPair{
		{Key: " prefix ", Value: "raw/path"},
		{Key: PropertyFSShadowing, Value: "true"},
	}}); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()
	if _, ok := r.Prefix(); ok {
		t.Fatal("whitespace-padded key matched the prefix property")
	}
	if _, ok := r.Version(); ok {
		t.Fatal("Version() found a property that was not present")
	}
	if r.FSShadowing() {
		t.Fatal("FSShadowing() accepted a value other than the enabled form")
	}
	if got := pboPrefixFromHeaders(r.Headers()); got != "" {
		t.Fatalf("signing prefix = %q, want empty", got)
	}
	headers := r.Headers()
	if len(headers) != 2 || headers[0].Key != " prefix " || headers[0].Value != "raw/path" ||
		headers[1] != (HeaderPair{Key: PropertyFSShadowing, Value: "true"}) {
		t.Fatalf("raw headers = %#v, want the exact original pairs", headers)
	}
}

func TestPackFile_RejectsInvalidWireFieldsBeforeTruncation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		input   Input
		opts    PackOptions
		wantErr error
	}{
		{
			name:    "NUL path",
			input:   Input{Path: "bad\x00path"},
			wantErr: ErrInvalidEntryPath,
		},
		{
			name:    "overlong path",
			input:   Input{Path: strings.Repeat("x", maxNameLen+1)},
			wantErr: ErrFileNameTooLong,
		},
		{
			name:    "empty property key",
			input:   Input{Path: "entry.txt"},
			opts:    PackOptions{Headers: []HeaderPair{{Value: "value"}}},
			wantErr: ErrInvalidHeaderProperty,
		},
		{
			name:    "NUL property key",
			input:   Input{Path: "entry.txt"},
			opts:    PackOptions{Headers: []HeaderPair{{Key: "key\x00tail", Value: "value"}}},
			wantErr: ErrInvalidHeaderProperty,
		},
		{
			name:    "NUL property value",
			input:   Input{Path: "entry.txt"},
			opts:    PackOptions{Headers: []HeaderPair{{Key: "key", Value: "value\x00tail"}}},
			wantErr: ErrInvalidHeaderProperty,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "existing.pbo")
			const original = "keep existing bytes"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}

			opened := false
			tc.input.Open = func() (io.ReadCloser, error) {
				opened = true
				return io.NopCloser(strings.NewReader("payload")), nil
			}
			_, err := PackFile(context.Background(), path, []Input{tc.input}, tc.opts)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("PackFile error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
			if opened {
				t.Fatal("input Open was called for invalid wire fields")
			}

			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			if string(got) != original {
				t.Fatalf("target changed to %q", got)
			}
		})
	}
}

func TestPack_RejectsInvalidPropertiesBeforeWriting(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "existing.pbo")
	const original = "keep existing bytes"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	_, err = Pack(context.Background(), f, []Input{{
		Path: "entry.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("payload")), nil
		},
	}}, PackOptions{Headers: []HeaderPair{{Key: "key", Value: "bad\x00value"}}})
	if !errors.Is(err, ErrInvalidHeaderProperty) {
		t.Fatalf("Pack error = %v, want ErrInvalidHeaderProperty", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != original {
		t.Fatalf("target changed to %q", got)
	}
}

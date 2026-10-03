// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestAutoCompressionMatchesFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		data string
		want bool
	}{
		{name: "text rvmat", path: "materials/a.rvmat", data: "surface = 1;", want: true},
		{name: "binary rvmat", path: "materials/a.rvmat", data: "\x00raP\x00\x00\x00\x00\x08\x00", want: true},
		{name: "mlod", path: "models/a.p3d", data: "MLOD\x00", want: true},
		{name: "odol", path: "models/a.p3d", data: "ODOL\x00", want: true},
		{name: "oprw", path: "world/a.wrp", data: "OPRW\x1c", want: true},
		{name: "8wvr", path: "world/a.wrp", data: "8WVR", want: true},
		{name: "unmeasured 9vbw", path: "world/a.wrp", data: "9VBW", want: false},
		{name: "unmeasured 0wzd", path: "world/a.wrp", data: "0WZD", want: false},
		{name: "unknown wrp", path: "world/a.wrp", data: "????", want: false},
		{name: "texheaders", path: "a.bin", data: "0DHT", want: true},
		{name: "areaflags map", path: "world/areaflags.map", want: true},
		{name: "unknown map", path: "world/other.map", want: false},
		{name: "RAP config", path: "config.bin", data: "\x00raP\x00\x00\x00\x00\x08\x00", want: true},
		{name: "unknown binary", path: "a.bin", data: "RAP\x00", want: false},
		{name: "paa", path: "a.paa", data: "any", want: true},
		{name: "ogg", path: "a.ogg", data: "OggS", want: false},
		{name: "text config", path: "a.cpp", data: "class CfgPatches {};", want: true},
		{name: "binary config extension", path: "a.cpp", data: "\x00\x01", want: false},
		{name: "text emat", path: "materials/a.emat", data: "surface = 1;", want: true},
		{name: "binary emat", path: "materials/a.emat", data: "\x00\x01", want: false},
		{name: "text bisurf", path: "surfaces/a.bisurf", data: "Density=1;", want: true},
		{name: "binary bisurf", path: "surfaces/a.bisurf", data: "\x00\x01", want: false},
		{name: "text cfg", path: "model.cfg", data: "class CfgModels {};", want: true},
		{name: "text csv", path: "stringtable.csv", data: "key,value\n", want: true},
		{name: "text layout", path: "screen.layout", data: "WidgetClass Root {};", want: true},
		{name: "text imageset", path: "icons.imageset", data: "ImageSetClass Icons {};", want: true},
		{name: "text styles", path: "prefabs.styles", data: "<WidgetStyles />", want: true},
		{name: "text ptc", path: "effects.ptc", data: "EffectDef Smoke {};", want: true},
		{name: "text meta", path: "texture.meta", data: "MetaFileClass {}", want: true},
		{name: "text markdown", path: "README.md", data: "# Mod documentation\n", want: true},
		{name: "binary markdown", path: "README.md", data: "\x00\x01", want: false},
		{name: "measured sqf expansion", path: "script.sqf", data: "class CfgPatches {};", want: false},
		{name: "binary fnt", path: "fonts/font.fnt", data: "FORM\x00\x00\x00\x00FNT!", want: true},
		{name: "valid tga", path: "images/a.tga", data: string([]byte{0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 24, 0}), want: true},
		{name: "invalid tga", path: "images/a.tga", data: "not a tga header!", want: false},
		{name: "pac", path: "a.pac", data: "binary", want: true},
		{name: "unknown extension", path: "a.unknown", data: "text", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, got := autoCompressionBounds(tt.path, []byte(tt.data))
			if got != tt.want {
				t.Fatalf("autoCompressionBounds(%q) eligible=%v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestSelectCompressionInputReplaysSniffedPrefix(t *testing.T) {
	t.Parallel()

	content := "MLOD\x00payload"
	input := Input{Path: "model.p3d", SizeHint: 512}
	opts := PackOptions{Compress: true}
	opts.applyDefaults()

	selection, err := selectCompressionInput(opts, nil, input, strings.NewReader(content))
	if err != nil {
		t.Fatalf("selectCompressionInput: %v", err)
	}
	if !selection.candidate {
		t.Fatal("useCompression=false, want true")
	}

	replayed, err := io.ReadAll(selection.source)
	if err != nil {
		t.Fatalf("read replayed source: %v", err)
	}
	if string(replayed) != content {
		t.Fatalf("replayed=%q, want %q", replayed, content)
	}
}

func TestSelectCompressionInputExplicitRulesSkipSniffing(t *testing.T) {
	t.Parallel()

	content := "ODOL\x00payload"
	input := Input{Path: "model.p3d"}
	opts := PackOptions{Compress: true, CompressRules: includeRules("*.p3d")}
	opts.applyDefaults()
	matcher, err := newCompressMatcher(opts.CompressRules, opts.CompressMatcherOptions)
	if err != nil {
		t.Fatalf("newCompressMatcher: %v", err)
	}

	selection, err := selectCompressionInput(opts, matcher, input, strings.NewReader(content))
	if err != nil {
		t.Fatalf("selectCompressionInput: %v", err)
	}
	if !selection.candidate {
		t.Fatal("useCompression=false, want explicit rule to override profile")
	}

	replayed, err := io.ReadAll(selection.source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if string(replayed) != content {
		t.Fatalf("source=%q, want %q", replayed, content)
	}
}

func TestSelectCompressionInputReplaysNonCandidate(t *testing.T) {
	t.Parallel()

	content := []byte("raw payload")
	input := Input{Path: "unknown.bin"}
	opts := PackOptions{Compress: true}
	opts.applyDefaults()

	selection, err := selectCompressionInput(opts, nil, input, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("selectCompressionInput: %v", err)
	}
	if selection.candidate {
		t.Fatal("useCompression=true, want unknown format skipped")
	}

	replayed, err := io.ReadAll(selection.source)
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	if !bytes.Equal(replayed, content) {
		t.Fatalf("source=%q, want %q", replayed, content)
	}
}

func TestAutomaticCompressionSizeBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		data []byte
		size int64
		want bool
		min  uint32
		max  uint32
	}{
		{name: "small paa included", path: "a.paa", size: 1024, want: true},
		{name: "large paa excluded", path: "a.paa", size: 32 << 10, want: false},
		{name: "small odol included", path: "a.p3d", data: []byte("ODOL"), size: 64 << 10, want: true},
		{name: "large odol excluded", path: "a.p3d", data: []byte("ODOL"), size: 256 << 10, want: false},
		{name: "large mlod included", path: "a.p3d", data: []byte("MLOD"), size: 1 << 20, want: true},
		{name: "large cpp included", path: "a.cpp", data: []byte("text"), size: 1 << 20, want: true},
		{name: "emat above profile minimum", path: "a.emat", data: []byte("text"), size: 256, want: true},
		{name: "emat below profile minimum", path: "a.emat", data: []byte("text"), size: 127, want: false},
		{name: "bisurf above profile minimum", path: "a.bisurf", data: []byte("Density=1;"), size: 256, want: true},
		{name: "bisurf below profile minimum", path: "a.bisurf", data: []byte("Density=1;"), size: 127, want: false},
		{name: "binary rvmat below profile minimum", path: "a.rvmat", data: []byte("\x00raP\x00\x00\x00\x00\x08\x00"), size: 256, want: false},
		{name: "binary rvmat above profile minimum", path: "a.rvmat", data: []byte("\x00raP\x00\x00\x00\x00\x08\x00"), size: 1024, want: true},
		{name: "global minimum narrows profile", path: "a.cpp", data: []byte("text"), size: 256, want: false, min: 512},
		{name: "global maximum narrows profile", path: "a.cpp", data: []byte("text"), size: 1 << 20, want: false, max: 512 << 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := PackOptions{Compress: true, MinCompressSize: tt.min, MaxCompressSize: tt.max}
			opts.applyDefaults()
			selection, err := selectCompressionInput(opts, nil, Input{Path: tt.path, SizeHint: tt.size}, bytes.NewReader(tt.data))
			if err != nil {
				t.Fatalf("selectCompressionInput: %v", err)
			}
			if selection.candidate != tt.want {
				t.Fatalf("candidate=%v, want %v", selection.candidate, tt.want)
			}
		})
	}
}

func TestPackAutomaticCompressionProfile(t *testing.T) {
	t.Parallel()

	payload := bytes.Repeat([]byte("class CfgPatches {};\n"), 128)
	input := Input{
		Path: "config.cpp",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	}
	out := &memWriteSeeker{}
	if _, err := Pack(t.Context(), out, []Input{input}, PackOptions{Compress: true}); err != nil {
		t.Fatalf("Pack: %v", err)
	}

	r, err := NewReaderFromReaderAt(bytes.NewReader(out.buf), int64(len(out.buf)))
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if !entries[0].IsCompressed() {
		t.Fatal("entry is not compressed by automatic profile")
	}
	got, err := r.ReadEntry("config.cpp")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip payload differs")
	}
}

func TestPackAutomaticCompressionProfileBoundsUnknownSizeODOL(t *testing.T) {
	t.Parallel()

	inputs := make([]Input, 0, 2)
	wantCompressed := map[string]bool{
		"small.p3d": true,
		"large.p3d": false,
	}
	wantPayloads := make(map[string][]byte, 2)
	for path, size := range map[string]int{"small.p3d": 64 << 10, "large.p3d": 256 << 10} {
		payload := append([]byte("ODOL"), bytes.Repeat([]byte("repetitive model payload\n"), size/25)...)
		sourcePayload := payload
		wantPayloads[path] = payload
		inputs = append(inputs, Input{
			Path: path,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(sourcePayload)), nil
			},
		})
	}

	completed := make(map[string]PackEntryProgress, len(inputs))
	out := &memWriteSeeker{}
	_, err := Pack(t.Context(), out, inputs, PackOptions{
		Compress: true,
		OnEntryDone: func(entry PackEntryProgress) {
			completed[entry.Path] = entry
		},
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	reader, err := NewReaderFromReaderAt(bytes.NewReader(out.buf), int64(len(out.buf)))
	if err != nil {
		t.Fatalf("NewReaderFromReaderAt: %v", err)
	}
	defer func() { _ = reader.Close() }()

	entries := reader.Entries()
	if len(entries) != len(wantCompressed) {
		t.Fatalf("entries=%d, want %d", len(entries), len(wantCompressed))
	}
	for _, entry := range entries {
		if got := entry.IsCompressed(); got != wantCompressed[entry.Path] {
			t.Errorf("%s compressed=%v, want %v", entry.Path, got, wantCompressed[entry.Path])
		}
		if !completed[entry.Path].CompressionCandidate {
			t.Errorf("%s was not classified as a compression candidate", entry.Path)
		}
		got, err := reader.ReadEntry(entry.Path)
		if err != nil {
			t.Errorf("ReadEntry(%s): %v", entry.Path, err)
			continue
		}
		if !bytes.Equal(got, wantPayloads[entry.Path]) {
			t.Errorf("%s decoded payload differs from source", entry.Path)
		}
	}
}

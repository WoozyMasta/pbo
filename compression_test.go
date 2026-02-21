package pbo

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/woozymasta/lzss"
	"github.com/woozymasta/pathrules"
)

func TestCompressMatcherMatch(t *testing.T) {
	t.Parallel()

	matcher, err := newCompressMatcher(includeRules(
		"*.paa",
		"textures/",
		"/addons/sounds/**/*.ogg",
	), pathrules.MatcherOptions{
		CaseInsensitive: true,
		DefaultAction:   pathrules.ActionExclude,
	})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{name: "extension rule", path: `foo\bar\a.paa`, want: true},
		{name: "dir-only rule", path: "addons/textures/a.bin", want: true},
		{name: "anchored root match", path: "addons/sounds/music/a.ogg", want: true},
		{name: "anchored root miss", path: "x/addons/sounds/music/a.ogg", want: false},
		{name: "no match", path: "addons/scripts/config.bin", want: false},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := matcher.Match(tc.path)
			if got != tc.want {
				t.Fatalf("Match(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestShouldCompressPolicy(t *testing.T) {
	t.Parallel()

	opts := PackOptions{
		Compress:        includeRules("*.bin"),
		MinCompressSize: 100,
		MaxCompressSize: 1000,
	}
	opts.applyDefaults()

	matcher, err := newCompressMatcher(opts.Compress, opts.CompressMatcherOptions)
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}

	if shouldCompress(opts, matcher, "a.bin", 99) {
		t.Fatal("expected false for file below min size")
	}

	if shouldCompress(opts, matcher, "a.bin", 1001) {
		t.Fatal("expected false for file above max size")
	}

	if shouldCompress(opts, matcher, "a.txt", 500) {
		t.Fatal("expected false for unmatched path")
	}

	if !shouldCompress(opts, matcher, "a.bin", 500) {
		t.Fatal("expected true for matched path in size range")
	}
}

func TestCompressMatcherIncludeExcludeRules(t *testing.T) {
	t.Parallel()

	matcher, err := newCompressMatcher([]pathrules.Rule{
		{Action: pathrules.ActionInclude, Pattern: "scripts/**"},
		{Action: pathrules.ActionExclude, Pattern: "scripts/tmp/**"},
		{Action: pathrules.ActionInclude, Pattern: "scripts/tmp/keep/**"},
	}, pathrules.MatcherOptions{
		CaseInsensitive: true,
		DefaultAction:   pathrules.ActionExclude,
	})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}

	if !matcher.Match("scripts/main.c") {
		t.Fatal("scripts/main.c must be included by rules")
	}

	if matcher.Match("scripts/tmp/a.c") {
		t.Fatal("scripts/tmp/a.c must be excluded by rules")
	}

	if !matcher.Match("SCRIPTS/TMP/keep/a.c") {
		t.Fatal("SCRIPTS/TMP/keep/a.c must be re-included by rules")
	}
}

func TestCompressMatcherInvalidRule(t *testing.T) {
	t.Parallel()

	_, err := newCompressMatcher([]pathrules.Rule{
		{
			Action:  pathrules.ActionUnknown,
			Pattern: "*.paa",
		},
	}, pathrules.MatcherOptions{
		DefaultAction: pathrules.ActionExclude,
	})
	if !errors.Is(err, ErrInvalidCompressPattern) {
		t.Fatalf("expected ErrInvalidCompressPattern, got %v", err)
	}
}

func TestCompressLZSSStreamMatchesSlice(t *testing.T) {
	t.Parallel()

	random := make([]byte, 8192)
	rng := rand.New(rand.NewSource(42))
	for i := range random {
		random[i] = byte(rng.Intn(256))
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{name: "repetitive", data: bytes.Repeat([]byte("abcabcabc"), 700)},
		{name: "text", data: []byte("class CfgPatches { class X { units[] = {}; }; };")},
		{name: "random", data: random},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stream bytes.Buffer
			inSize, outSize, err := lzss.CompressToWriter(&stream, bytes.NewReader(tc.data), nil)
			if err != nil {
				t.Fatalf("lzss.CompressToWriter: %v", err)
			}
			if inSize != int64(len(tc.data)) {
				t.Fatalf("input size = %d, want %d", inSize, len(tc.data))
			}

			want, err := compressLZSS(tc.data)
			if err != nil {
				t.Fatalf("compressLZSS: %v", err)
			}
			if outSize != int64(len(want)) {
				t.Fatalf("output size = %d, want %d", outSize, len(want))
			}

			if !bytes.Equal(stream.Bytes(), want) {
				t.Fatalf("stream output differs from slice output")
			}
		})
	}
}

func TestPack_CompressUnknownSizeHintBranch(t *testing.T) {
	t.Parallel()

	outPath := filepath.Join(t.TempDir(), "out.pbo")
	payload := bytes.Repeat([]byte("abcdef"), 2048)
	inputs := []Input{
		{
			Path: "data/a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
		},
	}

	opts := PackOptions{
		Compress:        includeRules("*.txt"),
		MinCompressSize: 1,
		MaxCompressSize: 8 * 1024 * 1024,
	}

	if _, err := PackFile(t.Context(), outPath, inputs, opts); err != nil {
		t.Fatalf("PackFile: %v", err)
	}

	r, err := Open(outPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries)=%d, want 1", len(entries))
	}
	if entries[0].IsCompressed() {
		t.Fatal("entry must stay uncompressed for unknown SizeHint scenario")
	}

	got, err := r.ReadEntry("data/a.txt")
	if err != nil {
		t.Fatalf("ReadEntry: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch after roundtrip")
	}
}

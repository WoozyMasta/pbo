// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Maxim Levchenko (WoozyMasta)
// Source: github.com/woozymasta/pbo

package pbo

import (
	"errors"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "slash", in: "/", want: ""},
		{name: "clean", in: "metricz/scripts/5_Mission", want: "metricz/scripts/5_Mission"},
		{name: "windows", in: `.\metricz\scripts\5_Mission\`, want: "metricz/scripts/5_Mission"},
		{name: "dot segments", in: "./a/../b//c.txt", want: "b/c.txt"},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := NormalizePath(tc.in)
			if got != tc.want {
				t.Fatalf("NormalizePath(%q)=%q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizePrefixHeader(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "slash", in: "metricz/scripts/5_Mission", want: `metricz\scripts\5_Mission`},
		{name: "backslash", in: `metricz\scripts\5_Mission\`, want: `metricz\scripts\5_Mission`},
		{name: "dot segments", in: "./a/../b/c", want: `b\c`},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := NormalizePrefixHeader(tc.in)
			if got != tc.want {
				t.Fatalf("NormalizePrefixHeader(%q)=%q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeArchiveEntryPath(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		got, err := normalizeArchiveEntryPath(`.\metricz/scripts\5_Mission\config.cpp`)
		if err != nil {
			t.Fatalf("normalizeArchiveEntryPath: %v", err)
		}

		want := `metricz\scripts\5_Mission\config.cpp`
		if got != want {
			t.Fatalf("normalizeArchiveEntryPath=%q, want %q", got, want)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()

		_, err := normalizeArchiveEntryPath("/")
		if !errors.Is(err, ErrInvalidEntryPath) {
			t.Fatalf("expected ErrInvalidEntryPath, got %v", err)
		}
	})
}

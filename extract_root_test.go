// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtract_RootContainsSymlinks(t *testing.T) {
	testCases := []struct {
		name       string
		entryPath  string
		linkName   string
		linkTarget string
		isDir      bool
		rawNames   bool
	}{
		{
			name:       "final symlink",
			entryPath:  "escape.txt",
			linkName:   "escape.txt",
			linkTarget: "outside.txt",
		},
		{
			name:       "intermediate symlink",
			entryPath:  "escape/payload.txt",
			linkName:   "escape",
			linkTarget: "outside",
			isDir:      true,
		},
		{
			name:       "raw names final symlink",
			entryPath:  "escape.txt",
			linkName:   "escape.txt",
			linkTarget: "outside.txt",
			rawNames:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			base := t.TempDir()
			destination := filepath.Join(base, "destination")
			outside := filepath.Join(base, "outside")
			if err := os.MkdirAll(destination, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(outside, 0o750); err != nil {
				t.Fatal(err)
			}

			linkTarget := filepath.Join(outside, tc.linkTarget)
			if tc.isDir {
				if err := os.MkdirAll(linkTarget, 0o750); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(linkTarget, []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}

			linkPath := filepath.Join(destination, tc.linkName)
			relativeTarget, err := filepath.Rel(filepath.Dir(linkPath), linkTarget)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(relativeTarget, linkPath); err != nil {
				t.Skipf("symlink creation is unavailable: %v", err)
			}

			pboPath := createManualPBOWithEntryPath(t, tc.entryPath, []byte("payload"))
			r, err := Open(pboPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()

			err = r.Extract(context.Background(), destination, ExtractOptions{
				MaxWorkers: 1,
				RawNames:   tc.rawNames,
			})
			if err == nil {
				t.Fatal("expected extraction through an outside symlink to fail")
			}

			if !tc.isDir {
				got, readErr := os.ReadFile(linkTarget)
				if readErr != nil {
					t.Fatalf("read outside target: %v", readErr)
				}
				if string(got) != "outside" {
					t.Fatalf("outside target changed to %q", got)
				}
			} else if _, statErr := os.Stat(filepath.Join(linkTarget, "payload.txt")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("outside payload must not be created, stat error = %v", statErr)
			}
		})
	}
}

func TestExtract_RootFollowsSymlinksWithinRoot(t *testing.T) {
	base := t.TempDir()
	destination := filepath.Join(base, "destination")
	targetDir := filepath.Join(destination, "target")
	if err := os.MkdirAll(targetDir, 0o750); err != nil {
		t.Fatal(err)
	}
	linkTarget, err := filepath.Rel(destination, targetDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, filepath.Join(destination, "alias")); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}

	pboPath := createManualPBOWithEntryPath(t, "alias/payload.txt", []byte("inside"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	if err := r.Extract(context.Background(), destination, ExtractOptions{MaxWorkers: 1}); err != nil {
		t.Fatalf("extract through in-root symlink: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(targetDir, "payload.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "inside" {
		t.Fatalf("payload = %q, want inside", got)
	}
}

func TestExtract_CaseSensitiveDirectories(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("case-sensitive directory names are required")
	}

	outPath := filepath.Join(t.TempDir(), "case.pbo")
	inputs := []Input{
		{Path: "A/x.txt", Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("upper")), nil
		}},
		{Path: "a/y.txt", Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("lower")), nil
		}},
	}
	if _, err := PackFile(context.Background(), outPath, inputs, PackOptions{}); err != nil {
		t.Fatal(err)
	}
	r, err := Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	destination := t.TempDir()
	if err := r.Extract(context.Background(), destination, ExtractOptions{MaxWorkers: 2}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"A/x.txt": "upper", "a/y.txt": "lower"} {
		got, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

func TestExtract_TruncateMode(t *testing.T) {
	pboPath := createManualPBO(t, []byte("hello"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	destination := t.TempDir()
	target := filepath.Join(destination, "a.txt")
	if err := os.WriteFile(target, []byte("stale contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.Extract(context.Background(), destination, ExtractOptions{
		MaxWorkers: 1,
		FileMode:   ExtractFileModeTruncate,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("truncated output = %q, want hello", got)
	}
}

func TestExtract_RejectsWindowsDeviceNames(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows device-name validation")
	}

	pboPath := createManualPBOWithEntryPath(t, "NUL", []byte("payload"))
	r, err := Open(pboPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	err = r.Extract(context.Background(), t.TempDir(), ExtractOptions{
		MaxWorkers: 1,
		RawNames:   true,
	})
	if err == nil {
		t.Fatal("expected Windows device name to be rejected")
	}
}

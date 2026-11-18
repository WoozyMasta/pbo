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
	"runtime"
	"strings"
	"testing"
)

func TestExtract_RootContainsSymlinks(t *testing.T) {
	t.Parallel()

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

func TestExtractWorkerCount(t *testing.T) {
	defaultWorkers := runtime.GOMAXPROCS(0)
	testCases := []struct {
		name          string
		requested     int
		workItemCount int
		want          int
	}{
		{name: "no work", requested: 8, workItemCount: 0, want: 0},
		{name: "requested workers", requested: 3, workItemCount: 8, want: 3},
		{name: "cap to work", requested: 100_000, workItemCount: 2, want: 2},
		{name: "default workers", requested: 0, workItemCount: defaultWorkers + 1, want: defaultWorkers},
		{name: "default capped to work", requested: -1, workItemCount: 1, want: 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractWorkerCount(tc.requested, tc.workItemCount); got != tc.want {
				t.Fatalf("extractWorkerCount(%d, %d) = %d, want %d", tc.requested, tc.workItemCount, got, tc.want)
			}
		})
	}
}

func TestExtract_ContinueOnErrorReturnsFirstAndExtractsRemaining(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "many-errors.pbo")
	inputs := []Input{
		{Path: "a.txt", Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("A"))), nil
		}},
		{Path: "b.txt", Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("B"))), nil
		}},
		{Path: "c.txt", Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("C"))), nil
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
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(destination, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var completed []string
	err = r.Extract(context.Background(), destination, ExtractOptions{
		MaxWorkers:      1,
		FileMode:        ExtractFileModeCreateOnly,
		ContinueOnError: true,
		OnEntryDone: func(entry EntryInfo, written int64, outputPath string) {
			if written != 1 {
				t.Errorf("callback bytes = %d, want 1", written)
			}
			if outputPath != filepath.Join(destination, entry.Path) {
				t.Errorf("callback path = %q, want %q", outputPath, filepath.Join(destination, entry.Path))
			}
			completed = append(completed, entry.Path)
		},
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected first create-only error, got %v", err)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("expected underlying path error, got %T", err)
	}
	if pathErr.Path != "a.txt" {
		t.Fatalf("first error path = %q, want a.txt", pathErr.Path)
	}

	got, err := os.ReadFile(filepath.Join(destination, "c.txt"))
	if err != nil {
		t.Fatalf("read later entry: %v", err)
	}
	if !bytes.Equal(got, []byte("C")) {
		t.Fatalf("later entry = %q, want C", got)
	}
	if len(completed) != 1 || completed[0] != "c.txt" {
		t.Fatalf("completed callbacks = %v, want [c.txt]", completed)
	}
}

func TestPrepareExtractWorkItemsRejectsOutputPathCollisions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		paths   []string
		wantErr error
	}{
		{
			name:    "same path with different separators",
			paths:   []string{`dir\file.txt`, "dir/file.txt"},
			wantErr: ErrDuplicateEntryPath,
		},
		{
			name:    "case-insensitive file collision",
			paths:   []string{"Dir/file.txt", "dir/FILE.txt"},
			wantErr: ErrDuplicateEntryPath,
		},
		{
			name:    "file before nested path",
			paths:   []string{"dir", "dir/file.txt"},
			wantErr: ErrDuplicateEntryPath,
		},
		{
			name:    "nested path before file",
			paths:   []string{"dir/file.txt", "dir"},
			wantErr: ErrDuplicateEntryPath,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			entries := make([]EntryInfo, len(tc.paths))
			for i, path := range tc.paths {
				entries[i].Path = path
			}

			_, err := prepareExtractWorkItems(entries)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("prepareExtractWorkItems error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

func TestExtractDuplicateRawNamesFailsBeforeWriting(t *testing.T) {
	t.Parallel()

	pboPath := createManualPBOWithNamedEntries(t, []manualEntry{
		{name: "duplicate.txt", data: []byte("first")},
		{name: "duplicate.txt", data: []byte("second")},
	})
	reader, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = reader.Close() }()

	outputDir := filepath.Join(t.TempDir(), "output")
	err = reader.Extract(context.Background(), outputDir, ExtractOptions{
		MaxWorkers: 2,
		RawNames:   true,
	})
	if !errors.Is(err, ErrDuplicateEntryPath) {
		t.Fatalf("Extract error = %v, want ErrDuplicateEntryPath", err)
	}

	files, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("ReadDir output: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("output contains %d files after collision error, want 0", len(files))
	}
}

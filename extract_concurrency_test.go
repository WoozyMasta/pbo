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
	"testing"
)

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

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// extractCopyBufferSize defines per-worker buffer size for file copy during extraction.
const extractCopyBufferSize = 64 * 1024

// extractWorkItem stores one selected entry with prepared output relative paths.
type extractWorkItem struct {
	relPath string
	relDir  string
	entry   EntryInfo
}

// Extract writes selected entries from the PBO to dstDir. Extraction is parallelized
// by MaxWorkers; on failure it returns the first encountered error.
func (r *Reader) Extract(ctx context.Context, dstDir string, opts ExtractOptions) error {
	if r == nil || r.ra == nil {
		return ErrNilReader
	}

	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return ErrClosed
	}

	workers := opts.MaxWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers < 1 {
		workers = 1
	}

	entries := r.entries
	if opts.Entries != nil {
		entries = opts.Entries
	}

	if len(entries) == 0 {
		return nil
	}

	if !opts.RawNames {
		sanitizedEntries, sanitizeErr := sanitizeEntryInfoPaths(entries)
		if sanitizeErr != nil {
			return sanitizeErr
		}

		entries = sanitizedEntries
	}

	fileMode := opts.FileMode
	if fileMode == "" {
		fileMode = ExtractFileModeAuto
	}

	dstRootAbs, err := filepath.Abs(dstDir)
	if err != nil {
		return fmt.Errorf("resolve output dir: %w", err)
	}

	if err := os.MkdirAll(dstRootAbs, 0o750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	workItems, err := prepareExtractWorkItems(entries)
	if err != nil {
		return err
	}

	if len(workItems) == 0 {
		return nil
	}

	if err := prepareExtractDirs(dstRootAbs, workItems); err != nil {
		return err
	}

	taskCh := make(chan extractWorkItem, len(workItems))
	errCh := make(chan error, len(workItems))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Go(func() {
			copyBuf := make([]byte, extractCopyBufferSize)
			for task := range taskCh {
				err := r.extractPreparedEntry(ctx, dstRootAbs, task, fileMode, copyBuf, opts.OnEntryDone)
				select {
				case errCh <- err:
				case <-ctx.Done():
					return
				}
			}
		})
	}

	for _, task := range workItems {
		select {
		case <-ctx.Done():
			close(taskCh)
			wg.Wait()
			return ctx.Err()
		case taskCh <- task:
		}
	}

	close(taskCh)
	wg.Wait()
	close(errCh)

	var first error
	for err := range errCh {
		if err != nil && first == nil {
			first = err
		}
	}

	return first
}

// prepareExtractWorkItems validates selected entries and prepares relative fs paths.
func prepareExtractWorkItems(entries []EntryInfo) ([]extractWorkItem, error) {
	workItems := make([]extractWorkItem, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Path) == "" {
			continue
		}

		normalizedPath, err := normalizeExtractEntryPath(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("normalize entry path %s: %w", entry.Path, err)
		}

		relPath := filepath.FromSlash(normalizedPath)
		relDir := filepath.Dir(relPath)
		if relDir == "." || relDir == "" {
			relDir = ""
		}

		workItems = append(workItems, extractWorkItem{
			entry:   entry,
			relPath: relPath,
			relDir:  relDir,
		})
	}

	return workItems, nil
}

// prepareExtractDirs creates all unique parent directories needed by work items.
func prepareExtractDirs(dstRootAbs string, workItems []extractWorkItem) error {
	seen := make(map[string]struct{}, len(workItems))
	for _, task := range workItems {
		if task.relDir == "" {
			continue
		}

		dirPath := filepath.Join(dstRootAbs, task.relDir)
		key := strings.ToLower(dirPath)
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		if err := os.MkdirAll(dirPath, 0o750); err != nil {
			return fmt.Errorf("create output directory %s: %w", dirPath, err)
		}
	}

	return nil
}

// extractPreparedEntry writes one prepared work item to destination root.
func (r *Reader) extractPreparedEntry(
	ctx context.Context,
	dstRootAbs string,
	task extractWorkItem,
	fileMode ExtractFileMode,
	copyBuf []byte,
	onEntryDone func(entry EntryInfo, written int64, outputPath string),
) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	outPath := filepath.Join(dstRootAbs, task.relPath)

	rc, err := r.openEntryByInfo(&task.entry, task.entry.Path)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	expectedSize := int64(task.entry.DataSize)
	if task.entry.OriginalSize > 0 {
		expectedSize = int64(task.entry.OriginalSize)
	}

	file, needsTruncate, err := openExtractFile(outPath, fileMode, expectedSize)
	if err != nil {
		return fmt.Errorf("open %s: %w", task.entry.Path, err)
	}

	written, copyErr := copyExtractData(file, rc, copyBuf)
	if copyErr == nil && needsTruncate {
		if truncErr := file.Truncate(written); truncErr != nil {
			_ = file.Close()
			return fmt.Errorf("truncate %s: %w", task.entry.Path, truncErr)
		}
	}

	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("write %s: %w", task.entry.Path, copyErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close %s: %w", task.entry.Path, closeErr)
	}

	if onEntryDone != nil {
		onEntryDone(task.entry, written, outPath)
	}

	return nil
}

// openExtractFile opens output path according to selected extract file mode.
func openExtractFile(path string, mode ExtractFileMode, expectedSize int64) (*os.File, bool, error) {
	switch mode {
	case ExtractFileModeAuto:
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, false, nil
		}

		if !os.IsExist(err) {
			return nil, false, err
		}

		file, truncErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		return file, false, truncErr
	case ExtractFileModeOverwriteSmart:
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return nil, false, err
		}

		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, false, err
		}

		needsTruncate := info.Size() > expectedSize
		return file, needsTruncate, nil
	case ExtractFileModeTruncate:
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		return file, false, err
	case ExtractFileModeCreateOnly:
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		return file, false, err
	default:
		return nil, false, fmt.Errorf("unknown extract file mode %q", mode)
	}
}

// copyExtractData copies one entry stream to output file using fixed worker buffer.
func copyExtractData(dst *os.File, src io.Reader, buf []byte) (int64, error) {
	if len(buf) == 0 {
		return 0, io.ErrShortBuffer
	}

	var total int64
	for {
		readN, readErr := src.Read(buf)
		if readN > 0 {
			writeN, writeErr := dst.Write(buf[:readN])
			total += int64(writeN)

			if writeErr != nil {
				return total, writeErr
			}

			if writeN != readN {
				return total, io.ErrShortWrite
			}
		}

		if readErr == nil {
			continue
		}

		if readErr == io.EOF {
			return total, nil
		}

		return total, readErr
	}
}

// normalizeExtractEntryPath normalizes entry path and rejects absolute/traversal inputs.
func normalizeExtractEntryPath(entryPath string) (string, error) {
	raw := strings.TrimSpace(entryPath)
	if raw == "" {
		return "", ErrInvalidExtractPath
	}
	if strings.ContainsRune(raw, 0) {
		return "", ErrInvalidExtractPath
	}
	if strings.HasPrefix(raw, `/`) || strings.HasPrefix(raw, `\`) {
		return "", ErrInvalidExtractPath
	}

	raw = strings.ReplaceAll(raw, `\`, `/`)
	if hasWindowsAbsDrivePrefix(raw) {
		return "", ErrInvalidExtractPath
	}

	parts := strings.Split(raw, `/`)
	cleanParts := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			return "", ErrInvalidExtractPath
		default:
			cleanParts = append(cleanParts, part)
		}
	}
	if len(cleanParts) == 0 {
		return "", ErrInvalidExtractPath
	}

	return strings.Join(cleanParts, `/`), nil
}

// hasWindowsAbsDrivePrefix reports whether path starts with drive-root prefix like C:/.
func hasWindowsAbsDrivePrefix(path string) bool {
	if len(path) < 3 {
		return false
	}

	return isASCIIAlpha(path[0]) && path[1] == ':' && path[2] == '/'
}

// isASCIIAlpha reports whether byte is ASCII latin letter.
func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

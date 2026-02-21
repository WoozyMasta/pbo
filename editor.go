// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Editor accumulates archive edit operations and applies them on Commit.
type Editor struct {
	path string
	ops  []editOperation
	opts EditOptions
}

// editOperation stores one staged editor operation.
type editOperation struct {
	inputs []Input
	paths  []string
	kind   editOperationKind
}

// editOperationKind identifies staged edit action type.
type editOperationKind uint8

const (
	// editOperationAdd appends new entries and fails on existing path.
	editOperationAdd editOperationKind = iota + 1
	// editOperationReplace rewrites existing entries.
	editOperationReplace
	// editOperationDelete removes exact paths.
	editOperationDelete
	// editOperationDeleteDir removes entries by directory prefix.
	editOperationDeleteDir
)

// OpenEditor creates staged editor for file-based archive rewrite workflow.
func OpenEditor(path string, opts EditOptions) (*Editor, error) {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return nil, ErrInvalidEntryPath
	}

	opts.applyDefaults()

	return &Editor{
		path: trimmedPath,
		opts: opts,
		ops:  make([]editOperation, 0, 8),
	}, nil
}

// Add schedules adding new entries and fails on path collision during commit.
func (e *Editor) Add(inputs ...Input) error {
	if e == nil {
		return ErrNilReader
	}

	normalized, err := normalizeEditorInputs(inputs)
	if err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	e.ops = append(e.ops, editOperation{
		kind:   editOperationAdd,
		inputs: normalized,
	})

	return nil
}

// Replace schedules replacing existing entries.
func (e *Editor) Replace(inputs ...Input) error {
	if e == nil {
		return ErrNilReader
	}

	normalized, err := normalizeEditorInputs(inputs)
	if err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	e.ops = append(e.ops, editOperation{
		kind:   editOperationReplace,
		inputs: normalized,
	})

	return nil
}

// Delete schedules exact-path removal.
func (e *Editor) Delete(paths ...string) error {
	if e == nil {
		return ErrNilReader
	}

	normalized, err := normalizeEditorPaths(paths)
	if err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	e.ops = append(e.ops, editOperation{
		kind:  editOperationDelete,
		paths: normalized,
	})

	return nil
}

// DeleteDir schedules directory-prefix removal.
func (e *Editor) DeleteDir(prefixes ...string) error {
	if e == nil {
		return ErrNilReader
	}

	normalized, err := normalizeEditorPaths(prefixes)
	if err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	e.ops = append(e.ops, editOperation{
		kind:  editOperationDeleteDir,
		paths: normalized,
	})

	return nil
}

// Commit applies all staged operations in one rewrite transaction.
func (e *Editor) Commit(ctx context.Context) (*PackResult, error) {
	if e == nil {
		return nil, ErrNilReader
	}

	if ctx == nil {
		ctx = context.Background()
	}

	backupPath := e.path + ".bak"
	if err := prepareBackupSlot(backupPath, e.opts.BackupKeep); err != nil {
		return nil, err
	}

	if err := os.Rename(e.path, backupPath); err != nil {
		return nil, fmt.Errorf("move archive to backup: %w", err)
	}

	res, err := e.commitFromBackup(ctx, backupPath)
	if err != nil {
		rollbackErr := rollbackFromBackup(e.path, backupPath)
		if rollbackErr != nil {
			return nil, fmt.Errorf("%v (rollback failed: %v)", err, rollbackErr)
		}

		return nil, err
	}

	if e.opts.BackupKeep == 0 {
		if err := removeIfExists(backupPath); err != nil {
			return nil, fmt.Errorf("remove backup: %w", err)
		}
	}

	return res, nil
}

// commitFromBackup writes edited archive from backup source.
func (e *Editor) commitFromBackup(ctx context.Context, backupPath string) (*PackResult, error) {
	srcFile, err := os.Open(backupPath)
	if err != nil {
		return nil, fmt.Errorf("open backup: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat backup: %w", err)
	}

	srcReader, err := NewReaderFromReaderAt(srcFile, srcInfo.Size())
	if err != nil {
		return nil, fmt.Errorf("parse backup: %w", err)
	}

	plan, err := buildEditPlan(srcReader.entries, e.ops)
	if err != nil {
		return nil, err
	}

	packOpts := e.opts.PackOptions
	if len(packOpts.Headers) == 0 {
		packOpts.Headers = srcReader.Headers()
	}

	dstFile, err := os.OpenFile(e.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create destination archive: %w", err)
	}

	res, writeErr := rewriteArchive(ctx, dstFile, srcFile, plan, packOpts)
	if writeErr != nil {
		_ = dstFile.Close()
		return nil, writeErr
	}

	if err := dstFile.Sync(); err != nil {
		_ = dstFile.Close()
		return nil, fmt.Errorf("sync destination archive: %w", err)
	}

	if err := dstFile.Close(); err != nil {
		return nil, fmt.Errorf("close destination archive: %w", err)
	}

	if err := writeSHA1Trailer(e.path); err != nil {
		return nil, fmt.Errorf("write SHA1 trailer: %w", err)
	}

	return res, nil
}

// normalizeEditorInputs validates and canonicalizes editor input list.
func normalizeEditorInputs(inputs []Input) ([]Input, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	normalized := make([]Input, 0, len(inputs))
	for i := range inputs {
		canonicalPath, err := normalizeEditorArchivePath(inputs[i].Path)
		if err != nil {
			return nil, fmt.Errorf("%w: input path %q", ErrInvalidEntryPath, inputs[i].Path)
		}

		item := inputs[i]
		item.Path = canonicalPath
		normalized = append(normalized, item)
	}

	return normalized, nil
}

// normalizeEditorPaths validates and canonicalizes editor path list.
func normalizeEditorPaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	out := make([]string, 0, len(paths))
	for _, raw := range paths {
		canonical, err := normalizeEditorArchivePath(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrInvalidEntryPath, raw)
		}

		out = append(out, canonical)
	}

	return out, nil
}

// normalizeEditorArchivePath converts path to canonical archive path form.
func normalizeEditorArchivePath(raw string) (string, error) {
	return normalizeArchiveEntryPath(raw)
}

// buildEditPlan applies staged operations to source entries and builds final write plan.
func buildEditPlan(sourceEntries []EntryInfo, ops []editOperation) ([]rewriteEntry, error) {
	state := make(map[string]rewriteEntry, len(sourceEntries))
	for i := range sourceEntries {
		path, err := normalizeEditorArchivePath(sourceEntries[i].Path)
		if err != nil {
			return nil, fmt.Errorf("%w: source entry path %q", ErrInvalidEntryPath, sourceEntries[i].Path)
		}

		key := editorPathKey(path)
		if _, exists := state[key]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateEntryPath, path)
		}

		entry := sourceEntries[i]
		entry.Path = path
		state[key] = rewriteEntry{
			path:   path,
			source: &entry,
		}
	}

	for _, op := range ops {
		switch op.kind {
		case editOperationAdd:
			if err := applyEditAdd(state, op.inputs); err != nil {
				return nil, err
			}
		case editOperationReplace:
			if err := applyEditReplace(state, op.inputs); err != nil {
				return nil, err
			}
		case editOperationDelete:
			applyEditDelete(state, op.paths)
		case editOperationDeleteDir:
			applyEditDeleteDir(state, op.paths)
		default:
			return nil, fmt.Errorf("unknown edit operation kind: %d", op.kind)
		}
	}

	plan := make([]rewriteEntry, 0, len(state))
	for _, item := range state {
		plan = append(plan, item)
	}

	sort.Slice(plan, func(i, j int) bool { return plan[i].path < plan[j].path })

	return plan, nil
}

// applyEditAdd adds new entries and fails on existing paths.
func applyEditAdd(state map[string]rewriteEntry, inputs []Input) error {
	for _, in := range inputs {
		key := editorPathKey(in.Path)
		if _, exists := state[key]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicateEntryPath, in.Path)
		}

		item := in
		state[key] = rewriteEntry{
			path:  item.Path,
			input: &item,
		}
	}

	return nil
}

// applyEditReplace replaces existing entries and fails on missing paths.
func applyEditReplace(state map[string]rewriteEntry, inputs []Input) error {
	for _, in := range inputs {
		key := editorPathKey(in.Path)
		if _, exists := state[key]; !exists {
			return fmt.Errorf("%w: %q", ErrEntryNotFound, in.Path)
		}

		item := in
		state[key] = rewriteEntry{
			path:  item.Path,
			input: &item,
		}
	}

	return nil
}

// applyEditDelete removes exact paths from state.
func applyEditDelete(state map[string]rewriteEntry, paths []string) {
	for _, path := range paths {
		delete(state, editorPathKey(path))
	}
}

// applyEditDeleteDir removes entries matching directory prefixes.
func applyEditDeleteDir(state map[string]rewriteEntry, prefixes []string) {
	for _, prefix := range prefixes {
		for key, item := range state {
			if hasEditorDirPrefix(item.path, prefix) {
				delete(state, key)
			}
		}
	}
}

// hasEditorDirPrefix reports whether path is equal to prefix or inside prefixed directory.
func hasEditorDirPrefix(path string, prefix string) bool {
	pathKey := editorPathKey(path)
	prefixKey := editorPathKey(prefix)

	return pathKey == prefixKey || strings.HasPrefix(pathKey, prefixKey+`\`)
}

// editorPathKey returns case-insensitive map key for archive path.
func editorPathKey(path string) string {
	return strings.ToLower(path)
}

// prepareBackupSlot rotates/removes existing backup generations before new commit.
func prepareBackupSlot(backupPath string, keep int) error {
	if keep < 0 {
		keep = 0
	}

	switch keep {
	case 0, 1:
		return removeIfExists(backupPath)
	default:
		oldest := fmt.Sprintf("%s.%d", backupPath, keep-1)
		if err := removeIfExists(oldest); err != nil {
			return err
		}

		for i := keep - 2; i >= 1; i-- {
			from := fmt.Sprintf("%s.%d", backupPath, i)
			to := fmt.Sprintf("%s.%d", backupPath, i+1)
			if err := renameIfExists(from, to); err != nil {
				return err
			}
		}

		return renameIfExists(backupPath, backupPath+".1")
	}
}

// renameIfExists renames source to destination when source exists.
func renameIfExists(from string, to string) error {
	_, err := os.Stat(from)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", from, err)
	}

	if err := removeIfExists(to); err != nil {
		return err
	}

	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("rename %s to %s: %w", from, to, err)
	}

	return nil
}

// removeIfExists removes file when present.
func removeIfExists(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) || err == nil {
		return nil
	}

	return fmt.Errorf("remove %s: %w", path, err)
}

// rollbackFromBackup restores backup on failed commit.
func rollbackFromBackup(path string, backupPath string) error {
	_ = os.Remove(path)

	if err := os.Rename(backupPath, path); err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}

	return nil
}

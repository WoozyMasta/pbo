// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Editor accumulates archive edit operations and applies them on Commit.
type Editor struct {
	path        string
	ops         []editOperation
	propertyOps []editorPropertyOperation
	opts        EditOptions
}

// editOperation stores one staged editor operation.
type editOperation struct {
	inputs      []Input
	paths       []string
	sourceIndex int
	kind        editOperationKind
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
	// editOperationReplaceAt rewrites an entry by its source index.
	editOperationReplaceAt
	// editOperationDeleteAt removes an entry by its source index.
	editOperationDeleteAt
)

// editorPropertyOperationKind identifies a staged property mutation.
type editorPropertyOperationKind uint8

const (
	// editorPropertySet stores or replaces one named property.
	editorPropertySet editorPropertyOperationKind = iota + 1
	// editorPropertyDelete removes a named property.
	editorPropertyDelete
	// editorPropertyClear removes all properties.
	editorPropertyClear
)

// editorPropertyOperation stores one staged header mutation.
type editorPropertyOperation struct {
	name  string
	value string
	kind  editorPropertyOperationKind
}

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

// ReplaceAt schedules replacing one source entry by its zero-based index.
func (e *Editor) ReplaceAt(sourceIndex int, input Input) error {
	if e == nil {
		return ErrNilReader
	}
	if sourceIndex < 0 {
		return fmt.Errorf("source index %d: %w", sourceIndex, ErrEntryNotFound)
	}

	normalized, err := normalizeEditorInputs([]Input{input})
	if err != nil {
		return err
	}

	e.ops = append(e.ops, editOperation{
		kind:        editOperationReplaceAt,
		inputs:      normalized,
		sourceIndex: sourceIndex,
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

// DeleteAt schedules removing one source entry by its zero-based index.
func (e *Editor) DeleteAt(sourceIndex int) error {
	if e == nil {
		return ErrNilReader
	}
	if sourceIndex < 0 {
		return fmt.Errorf("source index %d: %w", sourceIndex, ErrEntryNotFound)
	}

	e.ops = append(e.ops, editOperation{
		kind:        editOperationDeleteAt,
		sourceIndex: sourceIndex,
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

// SetProperty schedules setting one named property while preserving other source properties.
func (e *Editor) SetProperty(name string, value string) error {
	if e == nil {
		return ErrNilReader
	}
	if err := validateHeaderProperties([]HeaderPair{{Key: name, Value: value}}); err != nil {
		return err
	}

	e.propertyOps = append(e.propertyOps, editorPropertyOperation{
		kind:  editorPropertySet,
		name:  name,
		value: value,
	})

	return nil
}

// DeleteProperty schedules removing every source property with the given name.
func (e *Editor) DeleteProperty(name string) error {
	if e == nil {
		return ErrNilReader
	}
	if name == "" || strings.IndexByte(name, 0) >= 0 {
		return ErrInvalidHeaderProperty
	}

	e.propertyOps = append(e.propertyOps, editorPropertyOperation{
		kind: editorPropertyDelete,
		name: name,
	})

	return nil
}

// ClearProperties schedules removing all archive properties.
func (e *Editor) ClearProperties() error {
	if e == nil {
		return ErrNilReader
	}

	e.propertyOps = append(e.propertyOps, editorPropertyOperation{
		kind: editorPropertyClear,
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

	packOpts := e.opts.PackOptions
	srcReader, err := NewReaderFromReaderAtWithOptions(srcFile, srcInfo.Size(), ReaderOptions{
		SealedKey: packOpts.SealedKey,
	})
	if err != nil {
		return nil, fmt.Errorf("parse backup: %w", err)
	}

	plan, err := buildEditPlan(srcReader.entries, e.ops)
	if err != nil {
		return nil, err
	}

	packOpts.Headers = applyEditorProperties(srcReader.Headers(), packOpts.Headers, e.propertyOps)

	dstFile, err := os.OpenFile(e.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create destination archive: %w", err)
	}
	defer func() {
		if dstFile != nil {
			_ = dstFile.Close()
		}
	}()

	details, err := rewriteArchiveDetailed(ctx, dstFile, srcReader.ra, plan, packOpts)
	if err != nil {
		return nil, err
	}

	fileEnd, err := dstFile.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek end for trailer: %w", err)
	}

	hash1, err := computeHash1ForFile(details, dstFile, fileEnd, packOpts.SealedKey)
	if err != nil {
		return nil, fmt.Errorf("compute SHA1 trailer: %w", err)
	}

	var trailer [21]byte
	copy(trailer[1:], hash1)
	if _, err := dstFile.WriteAt(trailer[:], fileEnd); err != nil {
		return nil, fmt.Errorf("write SHA1 trailer: %w", err)
	}

	if err := dstFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync destination archive: %w", err)
	}

	if err := dstFile.Close(); err != nil {
		return nil, fmt.Errorf("close destination archive: %w", err)
	}
	dstFile = nil

	return details.packResult, nil
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

// plannedEditEntry tracks one ordered source or staged entry during plan construction.
type plannedEditEntry struct {
	item  rewriteEntry
	key   string
	alive bool
}

// buildEditPlan applies staged operations while preserving source order and raw paths.
func buildEditPlan(sourceEntries []EntryInfo, ops []editOperation) ([]rewriteEntry, error) {
	planned := make([]plannedEditEntry, 0, len(sourceEntries)+len(ops))
	byPath := make(map[string][]int, len(sourceEntries)+len(ops))

	for i := range sourceEntries {
		entry := new(EntryInfo)
		*entry = sourceEntries[i]
		key := editorPathKey(entry.Path)
		planned = append(planned, plannedEditEntry{
			item:  rewriteEntry{path: entry.Path, source: entry},
			key:   key,
			alive: true,
		})
		byPath[key] = append(byPath[key], i)
	}

	activeMatches := func(key string) []int {
		indices := byPath[key]
		matches := make([]int, 0, len(indices))
		for _, index := range indices {
			if planned[index].alive && planned[index].key == key {
				matches = append(matches, index)
			}
		}

		return matches
	}

	appendInput := func(input Input) {
		item := input
		index := len(planned)
		key := editorPathKey(item.Path)
		planned = append(planned, plannedEditEntry{
			item:  rewriteEntry{path: item.Path, input: &item},
			key:   key,
			alive: true,
		})
		byPath[key] = append(byPath[key], index)
	}

	replaceAt := func(index int, input Input) {
		item := input
		key := editorPathKey(item.Path)
		planned[index].item = rewriteEntry{path: item.Path, input: &item}
		planned[index].key = key
		byPath[key] = append(byPath[key], index)
	}

	for _, op := range ops {
		switch op.kind {
		case editOperationAdd:
			for _, input := range op.inputs {
				key := editorPathKey(input.Path)
				if len(activeMatches(key)) != 0 {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateEntryPath, input.Path)
				}

				appendInput(input)
			}

		case editOperationReplace:
			for _, input := range op.inputs {
				key := editorPathKey(input.Path)
				matches := activeMatches(key)
				if len(matches) == 0 {
					return nil, fmt.Errorf("%w: %q", ErrEntryNotFound, input.Path)
				}
				if len(matches) > 1 {
					return nil, fmt.Errorf("%w: %q", ErrAmbiguousEntryPath, input.Path)
				}

				replaceAt(matches[0], input)
			}

		case editOperationReplaceAt:
			if op.sourceIndex >= len(sourceEntries) || !planned[op.sourceIndex].alive {
				return nil, fmt.Errorf("source index %d: %w", op.sourceIndex, ErrEntryNotFound)
			}
			if len(op.inputs) != 1 {
				return nil, fmt.Errorf("source index %d: expected one replacement input", op.sourceIndex)
			}

			replaceAt(op.sourceIndex, op.inputs[0])

		case editOperationDelete:
			for _, path := range op.paths {
				key := editorPathKey(path)
				matches := activeMatches(key)
				if len(matches) > 1 {
					return nil, fmt.Errorf("%w: %q", ErrAmbiguousEntryPath, path)
				}

				if len(matches) == 1 {
					planned[matches[0]].alive = false
				}
			}

		case editOperationDeleteAt:
			if op.sourceIndex >= len(sourceEntries) || !planned[op.sourceIndex].alive {
				return nil, fmt.Errorf("source index %d: %w", op.sourceIndex, ErrEntryNotFound)
			}

			planned[op.sourceIndex].alive = false

		case editOperationDeleteDir:
			applyEditDeleteDir(planned, op.paths)

		default:
			return nil, fmt.Errorf("unknown edit operation kind: %d", op.kind)
		}
	}

	plan := make([]rewriteEntry, 0, len(planned))
	for i := range planned {
		if planned[i].alive {
			plan = append(plan, planned[i].item)
		}
	}

	return plan, nil
}

// applyEditorProperties overlays pack properties and staged mutations on source headers.
func applyEditorProperties(source []HeaderPair, pack []HeaderPair, ops []editorPropertyOperation) []HeaderPair {
	headers := append([]HeaderPair(nil), source...)
	for _, property := range pack {
		headers = setProperty(headers, property.Key, property.Value)
	}

	for _, op := range ops {
		switch op.kind {
		case editorPropertySet:
			headers = setProperty(headers, op.name, op.value)

		case editorPropertyDelete:
			headers = deleteProperty(headers, op.name)

		case editorPropertyClear:
			headers = nil
		}
	}

	return headers
}

// applyEditDeleteDir removes live entries matching normalized directory prefixes in one pass.
func applyEditDeleteDir(planned []plannedEditEntry, prefixes []string) {
	prefixKeys := editorDirPrefixKeys(prefixes)
	for i := range planned {
		if planned[i].alive && hasAnyEditorDirPrefixKey(planned[i].key, prefixKeys) {
			planned[i].alive = false
		}
	}
}

// editorDirPrefixKeys normalizes directory prefixes once before scanning entries.
func editorDirPrefixKeys(prefixes []string) []string {
	keys := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		keys[i] = editorPathKey(prefix)
	}

	return keys
}

// hasEditorDirPrefixKey compares already normalized archive lookup keys.
func hasEditorDirPrefixKey(pathKey string, prefixKey string) bool {
	if pathKey == prefixKey {
		return true
	}

	return len(pathKey) > len(prefixKey) &&
		strings.HasPrefix(pathKey, prefixKey) && pathKey[len(prefixKey)] == '/'
}

// hasAnyEditorDirPrefixKey matches a normalized path against prepared prefixes.
func hasAnyEditorDirPrefixKey(pathKey string, prefixKeys []string) bool {
	for _, prefixKey := range prefixKeys {
		if hasEditorDirPrefixKey(pathKey, prefixKey) {
			return true
		}
	}

	return false
}

// editorPathKey returns case-insensitive map key for archive path.
func editorPathKey(path string) string {
	return archiveLookupKey(path)
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

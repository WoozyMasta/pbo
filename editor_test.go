package pbo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditorCommit_AddReplaceDeleteDir(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	err := createTestPBO(pboPath, map[string][]byte{
		"dir/a.txt":      []byte("old-a"),
		"dir/sub/b.txt":  []byte("old-b"),
		"scripts/main.c": bytes.Repeat([]byte("class X {};"), 256),
	}, PackOptions{
		Compress:        true,
		CompressRules:   includeRules("*.c"),
		MinCompressSize: 1,
	})
	if err != nil {
		t.Fatalf("createTestPBO: %v", err)
	}

	editor, err := OpenEditor(pboPath, EditOptions{
		PackOptions: PackOptions{
			Compress:        true,
			CompressRules:   includeRules("*.txt", "*.c"),
			MinCompressSize: 1,
		},
		BackupKeep: 0,
	})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}

	if err := editor.Replace(Input{
		Path: "dir/a.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("new-a"))), nil
		},
		SizeHint: int64(len("new-a")),
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	newPayload := bytes.Repeat([]byte("compress-me"), 2048)
	if err := editor.Add(Input{
		Path: "new/new.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(newPayload)), nil
		},
		SizeHint: int64(len(newPayload)),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := editor.DeleteDir("dir/sub"); err != nil {
		t.Fatalf("DeleteDir: %v", err)
	}

	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	r, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if findEntry(entries, "dir\\sub\\b.txt") != nil {
		t.Fatal("dir\\sub\\b.txt must be deleted")
	}

	replaced := findEntry(entries, "dir\\a.txt")
	if replaced == nil {
		t.Fatal("dir\\a.txt must exist after replace")
	}

	replacedData, err := r.ReadEntry("dir\\a.txt")
	if err != nil {
		t.Fatalf("ReadEntry replaced: %v", err)
	}
	if string(replacedData) != "new-a" {
		t.Fatalf("replaced payload=%q, want %q", replacedData, "new-a")
	}

	added := findEntry(entries, "new\\new.txt")
	if added == nil {
		t.Fatal("new\\new.txt must exist after add")
	}
	if !added.IsCompressed() {
		t.Fatal("added txt entry must be compressed by edit PackOptions")
	}
}

func TestEditorCommit_ReplaceMissingPathFailsAndRestoresSource(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	err := createTestPBO(pboPath, map[string][]byte{
		"a.txt": []byte("orig"),
	}, PackOptions{})
	if err != nil {
		t.Fatalf("createTestPBO: %v", err)
	}

	editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}

	if err := editor.Replace(Input{
		Path: "missing.txt",
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("x"))), nil
		},
		SizeHint: 1,
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	_, err = editor.Commit(context.Background())
	if !errors.Is(err, ErrEntryNotFound) {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}

	got, err := readEntryFromFile(pboPath, "a.txt")
	if err != nil {
		t.Fatalf("readEntryFromFile: %v", err)
	}
	if string(got) != "orig" {
		t.Fatalf("restored payload=%q, want %q", got, "orig")
	}
}

func TestEditorCommit_InputOpenErrorRollsBack(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	err := createTestPBO(pboPath, map[string][]byte{
		"a.txt": []byte("orig"),
	}, PackOptions{})
	if err != nil {
		t.Fatalf("createTestPBO: %v", err)
	}

	editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}

	if err := editor.Replace(Input{
		Path: "a.txt",
		Open: func() (io.ReadCloser, error) {
			return nil, errors.New("boom")
		},
		SizeHint: 1,
	}); err != nil {
		t.Fatalf("Replace: %v", err)
	}

	_, err = editor.Commit(context.Background())
	if err == nil {
		t.Fatal("Commit must fail")
	}

	got, readErr := readEntryFromFile(pboPath, "a.txt")
	if readErr != nil {
		t.Fatalf("readEntryFromFile: %v", readErr)
	}
	if string(got) != "orig" {
		t.Fatalf("restored payload=%q, want %q", got, "orig")
	}
}

func TestEditorCommit_BackupKeepPolicies(t *testing.T) {
	t.Parallel()

	t.Run("keep0 removes backup", func(t *testing.T) {
		t.Parallel()

		pboPath := filepath.Join(t.TempDir(), "archive.pbo")
		err := createTestPBO(pboPath, map[string][]byte{
			"a.txt": []byte("v0"),
		}, PackOptions{})
		if err != nil {
			t.Fatalf("createTestPBO: %v", err)
		}

		editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
		if err != nil {
			t.Fatalf("OpenEditor: %v", err)
		}

		if err := editor.Replace(Input{
			Path: "a.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader([]byte("v1"))), nil
			},
			SizeHint: 2,
		}); err != nil {
			t.Fatalf("Replace: %v", err)
		}

		if _, err := editor.Commit(context.Background()); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		if _, err := os.Stat(pboPath + ".bak"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf(".bak must be removed for BackupKeep=0, stat err=%v", err)
		}
	})

	t.Run("keep2 rotates backups", func(t *testing.T) {
		t.Parallel()

		pboPath := filepath.Join(t.TempDir(), "archive.pbo")
		err := createTestPBO(pboPath, map[string][]byte{
			"a.txt": []byte("v0"),
		}, PackOptions{})
		if err != nil {
			t.Fatalf("createTestPBO: %v", err)
		}

		replaceAndCommit := func(value string) {
			t.Helper()

			editor, openErr := OpenEditor(pboPath, EditOptions{BackupKeep: 2})
			if openErr != nil {
				t.Fatalf("OpenEditor: %v", openErr)
			}

			if replaceErr := editor.Replace(Input{
				Path: "a.txt",
				Open: func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader([]byte(value))), nil
				},
				SizeHint: int64(len(value)),
			}); replaceErr != nil {
				t.Fatalf("Replace: %v", replaceErr)
			}

			if _, commitErr := editor.Commit(context.Background()); commitErr != nil {
				t.Fatalf("Commit: %v", commitErr)
			}
		}

		replaceAndCommit("v1")
		replaceAndCommit("v2")

		currentBak, err := readEntryFromFile(pboPath+".bak", "a.txt")
		if err != nil {
			t.Fatalf("read current bak: %v", err)
		}
		if string(currentBak) != "v1" {
			t.Fatalf("current bak payload=%q, want %q", currentBak, "v1")
		}

		previousBak, err := readEntryFromFile(pboPath+".bak.1", "a.txt")
		if err != nil {
			t.Fatalf("read previous bak: %v", err)
		}
		if string(previousBak) != "v0" {
			t.Fatalf("previous bak payload=%q, want %q", previousBak, "v0")
		}
	})
}

func TestEditorCommit_PreservesRawEntryOrderAndPackedBytes(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	untouchedPayload := []byte{0x91, 0x00, 0x37, 0xff}
	writeRawEditorArchive(t, pboPath, nil, []rawEditorEntry{
		{
			path:         "z//odd name.bin",
			data:         untouchedPayload,
			mime:         MimeCompress,
			originalSize: 12,
			timestamp:    1234,
		},
		{path: "target.txt", data: []byte("old")},
		{path: "a.txt", data: []byte("last")},
	})

	editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}
	if err := editor.Replace(editorInputForTest("target.txt", []byte("new"))); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if err := editor.Add(editorInputForTest("new.txt", []byte("added"))); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	r, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	wantPaths := []string{"z//odd name.bin", "target.txt", "a.txt", "new.txt"}
	if len(entries) != len(wantPaths) {
		t.Fatalf("entry count=%d, want %d", len(entries), len(wantPaths))
	}
	for i, want := range wantPaths {
		if entries[i].Path != want {
			t.Fatalf("entry %d path=%q, want raw path %q", i, entries[i].Path, want)
		}
	}
	if entries[0].MimeType != MimeCompress || entries[0].OriginalSize != 12 || entries[0].TimeStamp != 1234 {
		t.Fatalf("untouched metadata changed: %+v", entries[0])
	}

	var packed bytes.Buffer
	if _, err := r.CopyPackedEntryInfoTo(entries[0], &packed); err != nil {
		t.Fatalf("CopyPackedEntryInfoTo: %v", err)
	}
	if !bytes.Equal(packed.Bytes(), untouchedPayload) {
		t.Fatalf("packed payload=%x, want %x", packed.Bytes(), untouchedPayload)
	}
}

func TestEditorCommit_DuplicatePathsRequireSpecificEntryAPI(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	writeRawEditorArchive(t, pboPath, nil, []rawEditorEntry{
		{path: "dup.txt", data: []byte("first")},
		{path: "dup.txt", data: []byte("second")},
	})

	editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}
	if err := editor.Replace(editorInputForTest("dup.txt", []byte("ambiguous"))); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := editor.Commit(context.Background()); !errors.Is(err, ErrAmbiguousEntryPath) {
		t.Fatalf("Commit error=%v, want ErrAmbiguousEntryPath", err)
	}

	editor, err = OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor for indexed replacement: %v", err)
	}
	if err := editor.ReplaceAt(1, editorInputForTest("dup.txt", []byte("second-updated"))); err != nil {
		t.Fatalf("ReplaceAt: %v", err)
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit indexed replacement: %v", err)
	}

	r, err := Open(pboPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) != 2 {
		t.Fatalf("entry count=%d, want 2", len(entries))
	}
	firstReader, err := r.OpenEntryInfo(entries[0])
	if err != nil {
		t.Fatalf("OpenEntryInfo first: %v", err)
	}
	first, err := io.ReadAll(firstReader)
	_ = firstReader.Close()
	if err != nil {
		t.Fatalf("read first duplicate: %v", err)
	}
	secondReader, err := r.OpenEntryInfo(entries[1])
	if err != nil {
		t.Fatalf("OpenEntryInfo second: %v", err)
	}
	second, err := io.ReadAll(secondReader)
	_ = secondReader.Close()
	if err != nil {
		t.Fatalf("read second duplicate: %v", err)
	}
	if string(first) != "first" || string(second) != "second-updated" {
		t.Fatalf("duplicate payloads=(%q, %q), want (first, second-updated)", first, second)
	}
}

func TestEditorCommit_PreservesAndMutatesProperties(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	writeRawEditorArchive(t, pboPath, []HeaderPair{
		{Key: "prefix", Value: `source\prefix`},
		{Key: "author", Value: "source"},
		{Key: "opaque", Value: "preserved"},
		{Key: "remove", Value: "old"},
	}, []rawEditorEntry{{path: "file.txt", data: []byte("payload")}})

	editor, err := OpenEditor(pboPath, EditOptions{
		PackOptions: PackOptions{Headers: []HeaderPair{
			{Key: "author", Value: "pack option"},
			{Key: "added", Value: "from pack options"},
		}},
		BackupKeep: 0,
	})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}
	if err := editor.SetProperty("author", "explicit"); err != nil {
		t.Fatalf("SetProperty: %v", err)
	}
	if err := editor.DeleteProperty("remove"); err != nil {
		t.Fatalf("DeleteProperty: %v", err)
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	headers, err := ReadHeaders(pboPath)
	if err != nil {
		t.Fatalf("ReadHeaders: %v", err)
	}
	want := []HeaderPair{
		{Key: "prefix", Value: `source\prefix`},
		{Key: "author", Value: "explicit"},
		{Key: "opaque", Value: "preserved"},
		{Key: "added", Value: "from pack options"},
	}
	if !equalHeaderPairs(headers, want) {
		t.Fatalf("headers=%+v, want %+v", headers, want)
	}
}

func TestEditorCommit_ClearProperties(t *testing.T) {
	t.Parallel()

	pboPath := filepath.Join(t.TempDir(), "archive.pbo")
	writeRawEditorArchive(t, pboPath, []HeaderPair{{Key: "prefix", Value: "source"}}, []rawEditorEntry{
		{path: "file.txt", data: []byte("payload")},
	})

	editor, err := OpenEditor(pboPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}
	if err := editor.ClearProperties(); err != nil {
		t.Fatalf("ClearProperties: %v", err)
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	headers, err := ReadHeaders(pboPath)
	if err != nil {
		t.Fatalf("ReadHeaders: %v", err)
	}
	if len(headers) != 0 {
		t.Fatalf("headers=%+v, want none", headers)
	}
}

func TestBuildEditPlan_DeleteDirRespectsPathBoundary(t *testing.T) {
	t.Parallel()

	entries := []EntryInfo{
		{Path: "dir/sub"},
		{Path: "dir/sub/file.txt"},
		{Path: "dir/submarine/file.txt"},
		{Path: "other/file.txt"},
	}
	plan, err := buildEditPlan(entries, []editOperation{{
		kind:  editOperationDeleteDir,
		paths: []string{"dir/sub"},
	}})
	if err != nil {
		t.Fatalf("buildEditPlan: %v", err)
	}

	wantPaths := []string{"dir/submarine/file.txt", "other/file.txt"}
	if len(plan) != len(wantPaths) {
		t.Fatalf("plan length=%d, want %d", len(plan), len(wantPaths))
	}
	for i, want := range wantPaths {
		if plan[i].path != want {
			t.Fatalf("plan[%d].path=%q, want %q", i, plan[i].path, want)
		}
	}
}

func createTestPBO(path string, files map[string][]byte, opts PackOptions) error {
	inputs := make([]Input, 0, len(files))
	for filePath, payload := range files {
		localPath := filePath
		localPayload := append([]byte(nil), payload...)
		inputs = append(inputs, Input{
			Path: localPath,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(localPayload)), nil
			},
			SizeHint: int64(len(localPayload)),
		})
	}

	_, err := PackFile(context.Background(), path, inputs, opts)
	return err
}

// rawEditorEntry describes one exact index record and packed payload for editor tests.
type rawEditorEntry struct {
	path         string
	data         []byte
	mime         MimeType
	originalSize uint32
	timestamp    uint32
}

// writeRawEditorArchive writes a minimal PBO without normalizing entry paths.
func writeRawEditorArchive(t *testing.T, path string, headers []HeaderPair, entries []rawEditorEntry) {
	t.Helper()

	var archive bytes.Buffer
	fixedHeader := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(fixedHeader[1:5], uint32(MimeHeader))
	archive.Write(fixedHeader)
	for _, header := range headers {
		archive.WriteString(header.Key)
		archive.WriteByte(0)
		archive.WriteString(header.Value)
		archive.WriteByte(0)
	}
	archive.WriteByte(0)

	for _, entry := range entries {
		archive.WriteString(entry.path)
		archive.WriteByte(0)
		var fields [20]byte
		binary.LittleEndian.PutUint32(fields[0:4], uint32(entry.mime))
		binary.LittleEndian.PutUint32(fields[4:8], entry.originalSize)
		binary.LittleEndian.PutUint32(fields[12:16], entry.timestamp)
		binary.LittleEndian.PutUint32(fields[16:20], uint32(len(entry.data)))
		archive.Write(fields[:])
	}
	archive.WriteByte(0)
	archive.Write(make([]byte, 20))
	for _, entry := range entries {
		archive.Write(entry.data)
	}

	if err := os.WriteFile(path, archive.Bytes(), 0o600); err != nil {
		t.Fatalf("write raw editor archive: %v", err)
	}
}

// editorInputForTest returns a repeatable input backed by a copied payload.
func editorInputForTest(path string, payload []byte) Input {
	data := append([]byte(nil), payload...)
	return Input{
		Path: path,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		},
		SizeHint: int64(len(data)),
	}
}

// equalHeaderPairs compares ordered property sequences.
func equalHeaderPairs(left []HeaderPair, right []HeaderPair) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}

	return true
}

func findEntry(entries []EntryInfo, path string) *EntryInfo {
	for i := range entries {
		if stringsEqualFold(entries[i].Path, path) {
			return &entries[i]
		}
	}

	return nil
}

func readEntryFromFile(path string, entryPath string) ([]byte, error) {
	r, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()

	return r.ReadEntry(entryPath)
}

func stringsEqualFold(left string, right string) bool {
	return strings.EqualFold(left, right)
}

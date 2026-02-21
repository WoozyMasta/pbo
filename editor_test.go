package pbo

import (
	"bytes"
	"context"
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
		Compress:        includeRules("*.c"),
		MinCompressSize: 1,
	})
	if err != nil {
		t.Fatalf("createTestPBO: %v", err)
	}

	editor, err := OpenEditor(pboPath, EditOptions{
		PackOptions: PackOptions{
			Compress:        includeRules("*.txt", "*.c"),
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

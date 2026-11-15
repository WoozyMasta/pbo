package pbo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCanonicalPBOReaderExtractEditor exercises the public read, extract, and edit paths on original-tool PBOs.
func TestCanonicalPBOReaderExtractEditor(t *testing.T) {
	manifest := loadCanonicalCorpusManifest(t)
	source := loadCanonicalSourceManifest(t, manifest)
	sourceHashes := canonicalSourceHashes(source)

	for _, artifact := range manifest.PBOOutputs {
		t.Run(artifact.ID, func(t *testing.T) {
			expectedHashes := sourceHashes
			if artifact.PayloadManifest.Path != "" {
				payload := loadCanonicalPayloadManifest(t, artifact)
				expectedHashes = canonicalSourceHashes(canonicalSourceManifest{Files: payload.Files})
			}

			pboPath := filepath.Join(canonicalCorpusDir, filepath.FromSlash(artifact.Path))
			reader, err := Open(pboPath)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = reader.Close() }()

			assertReaderHeaders(t, reader, artifact.Properties)
			entries := reader.Entries()
			if len(entries) != artifact.EntryCount {
				t.Fatalf("entries=%d, want %d", len(entries), artifact.EntryCount)
			}
			trailer, ok := reader.SHA1Trailer()
			if !ok || hex.EncodeToString(trailer[:]) != artifact.TrailerSHA1 {
				t.Fatalf("SHA1Trailer=(%x, %t), want %s", trailer, ok, artifact.TrailerSHA1)
			}

			extractDir := filepath.Join(t.TempDir(), "extract")
			if err := reader.Extract(
				context.Background(), extractDir, ExtractOptions{MaxWorkers: 2},
			); err != nil {
				t.Fatalf("Extract: %v", err)
			}

			extractedHashes := hashExtractedFiles(t, extractDir)
			assertCorpusHashMapsEqual(
				t, extractedHashes,
				expectedHashes,
				"extracted files vs payload manifest",
			)
			assertNoOpEditorPreservesPBO(t, pboPath, artifact)
		})
	}
}

// TestPackFileFromCanonicalSource packs the tracked source tree and verifies its decoded output.
func TestPackFileFromCanonicalSource(t *testing.T) {
	manifest := loadCanonicalCorpusManifest(t)
	source := loadCanonicalSourceManifest(t, manifest)
	inputs := canonicalSourceInputs(t, source)
	outputPath := filepath.Join(t.TempDir(), "source.pbo")
	properties := []HeaderPair{
		{Key: "prefix", Value: `canonical\dayz\filebank`},
		{Key: "author", Value: "canonical"},
		{Key: "version", Value: "1"},
	}
	result, err := PackFile(
		context.Background(), outputPath, inputs, PackOptions{Headers: properties},
	)
	if err != nil {
		t.Fatalf("PackFile: %v", err)
	}
	if result.WrittenEntries != source.FileCount {
		t.Fatalf("written entries=%d, want %d", result.WrittenEntries, source.FileCount)
	}

	reader, err := Open(outputPath)
	if err != nil {
		t.Fatalf("Open packed PBO: %v", err)
	}
	defer func() { _ = reader.Close() }()

	assertReaderHeaders(t, reader, map[string]string{
		"prefix":  "canonical\\dayz\\filebank",
		"author":  "canonical",
		"version": "1",
	})
	if _, ok := reader.SHA1Trailer(); !ok {
		t.Fatal("PackFile output has no valid SHA-1 trailer")
	}

	entries := reader.Entries()
	if len(entries) != source.FileCount {
		t.Fatalf("decoded entries=%d, want %d", len(entries), source.FileCount)
	}
	extractDir := filepath.Join(t.TempDir(), "extract")
	if err := reader.Extract(
		context.Background(), extractDir, ExtractOptions{MaxWorkers: 2},
	); err != nil {
		t.Fatalf("Extract packed PBO: %v", err)
	}

	assertCorpusHashMapsEqual(
		t, hashExtractedFiles(t, extractDir),
		canonicalSourceHashes(source),
		"packed PBO extraction vs source manifest",
	)
}

// TestPackFileFromArmaAddonBuilderPayloads repacks decoded entries against the independent payload manifest.
func TestPackFileFromArmaAddonBuilderPayloads(t *testing.T) {
	manifest := loadCanonicalCorpusManifest(t)
	var artifact canonicalPBOArtifact
	for _, candidate := range manifest.PBOOutputs {
		if candidate.ID == "arma-addonbuilder" {
			artifact = candidate
			break
		}
	}
	if artifact.Path == "" || artifact.PayloadManifest.Path == "" {
		t.Fatal("Arma AddonBuilder fixture or payload manifest is missing")
	}

	payload := loadCanonicalPayloadManifest(t, artifact)
	sourcePath := filepath.Join(canonicalCorpusDir, filepath.FromSlash(artifact.Path))
	source, err := Open(sourcePath)
	if err != nil {
		t.Fatalf("Open source PBO: %v", err)
	}
	defer func() { _ = source.Close() }()

	entries := source.Entries()
	inputs := make([]Input, 0, len(entries))
	for _, entry := range entries {
		size := entry.DataSize
		if entry.OriginalSize > 0 {
			size = entry.OriginalSize
		}
		inputs = append(inputs, Input{
			Path:     entry.Path,
			SizeHint: int64(size),
			ModTime:  time.Unix(int64(entry.TimeStamp), 0).UTC(),
			Open: func() (io.ReadCloser, error) {
				return source.OpenEntryInfo(entry)
			},
		})
	}

	outputPath := filepath.Join(t.TempDir(), "repacked.pbo")
	result, err := PackFile(
		context.Background(), outputPath, inputs, PackOptions{Headers: source.Headers()},
	)
	if err != nil {
		t.Fatalf("PackFile: %v", err)
	}
	if result.WrittenEntries != payload.FileCount {
		t.Fatalf("written entries=%d, want %d", result.WrittenEntries, payload.FileCount)
	}

	packed, err := Open(outputPath)
	if err != nil {
		t.Fatalf("Open repacked PBO: %v", err)
	}
	defer func() { _ = packed.Close() }()

	if !equalHeaderPairs(source.Headers(), packed.Headers()) {
		t.Fatalf("PackFile changed headers: got %v, want %v", packed.Headers(), source.Headers())
	}
	if _, ok := packed.SHA1Trailer(); !ok {
		t.Fatal("repacked PBO has no valid SHA-1 trailer")
	}

	extractDir := filepath.Join(t.TempDir(), "extract")
	if err := packed.Extract(
		context.Background(), extractDir, ExtractOptions{MaxWorkers: 2},
	); err != nil {
		t.Fatalf("Extract repacked PBO: %v", err)
	}
	assertCorpusHashMapsEqual(
		t,
		hashExtractedFiles(t, extractDir),
		canonicalSourceHashes(canonicalSourceManifest{Files: payload.Files}),
		"repacked AddonBuilder payloads",
	)
}

// canonicalSourceHashes maps source-relative paths to their pinned SHA-256 values.
func canonicalSourceHashes(source canonicalSourceManifest) map[string]string {
	hashes := make(map[string]string, len(source.Files))
	for _, file := range source.Files {
		hashes[filepath.ToSlash(file.Path)] = strings.ToLower(file.SHA256)
	}

	return hashes
}

// canonicalSourceInputs opens the manifest's source files as packer inputs.
func canonicalSourceInputs(t *testing.T, source canonicalSourceManifest) []Input {
	t.Helper()

	inputs := make([]Input, 0, len(source.Files))
	for _, file := range source.Files {
		path := filepath.Join(canonicalCorpusDir, "source", filepath.FromSlash(file.Path))
		if info, err := os.Stat(path); err != nil {
			t.Fatalf("stat source %s: %v", file.Path, err)
		} else if info.Size() != file.Bytes {
			t.Fatalf("source %s size=%d, want %d", file.Path, info.Size(), file.Bytes)
		}

		inputPath := path
		inputs = append(inputs, Input{
			Path:     filepath.ToSlash(file.Path),
			SizeHint: file.Bytes,
			ModTime:  time.Unix(1_700_000_000, 0).UTC(),
			Open: func() (io.ReadCloser, error) {
				return os.Open(inputPath)
			},
		})
	}

	return inputs
}

// hashExtractedFiles hashes every file under an extraction root by slash-separated relative path.
func hashExtractedFiles(t *testing.T, root string) map[string]string {
	t.Helper()

	hashes := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}

		digest := sha256.New()
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}

		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(relative)] = hex.EncodeToString(digest.Sum(nil))
		return nil
	})
	if err != nil {
		t.Fatalf("walk extracted tree: %v", err)
	}

	return hashes
}

// assertReaderHeaders compares PBO properties against fixture metadata without imposing map order.
func assertReaderHeaders(t *testing.T, reader *Reader, expected map[string]string) {
	t.Helper()

	headers := reader.Headers()
	actual := make(map[string]string, len(headers))
	for _, header := range headers {
		if _, duplicate := actual[header.Key]; duplicate {
			t.Fatalf("duplicate header property %q", header.Key)
		}
		actual[header.Key] = header.Value
	}
	if !equalHeaderPropertyMap(actual, expected) {
		t.Fatalf("headers=%v, want %v", actual, expected)
	}
}

// assertNoOpEditorPreservesPBO verifies index order, metadata, headers, packed payloads, and trailer.
func assertNoOpEditorPreservesPBO(t *testing.T, sourcePath string, artifact canonicalPBOArtifact) {
	t.Helper()

	originalBytes := readCorpusFile(t, sourcePath)
	editedPath := filepath.Join(t.TempDir(), "edited.pbo")
	if err := os.WriteFile(editedPath, originalBytes, 0o600); err != nil {
		t.Fatalf("copy fixture PBO: %v", err)
	}

	editor, err := OpenEditor(editedPath, EditOptions{BackupKeep: 0})
	if err != nil {
		t.Fatalf("OpenEditor: %v", err)
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	original, err := Open(sourcePath)
	if err != nil {
		t.Fatalf("open source PBO: %v", err)
	}
	defer func() { _ = original.Close() }()

	edited, err := Open(editedPath)
	if err != nil {
		t.Fatalf("open edited PBO: %v", err)
	}
	defer func() { _ = edited.Close() }()

	if !equalHeaderPairs(original.Headers(), edited.Headers()) {
		t.Fatalf("Editor changed ordered headers: got %v, want %v", edited.Headers(), original.Headers())
	}

	originalEntries, editedEntries := original.Entries(), edited.Entries()
	if len(editedEntries) != len(originalEntries) {
		t.Fatalf("Editor changed entry count: got %d, want %d", len(editedEntries), len(originalEntries))
	}

	for i, before := range originalEntries {
		after := editedEntries[i]
		if after != before {
			t.Fatalf("Editor changed entry %d metadata: got %+v, want %+v", i, after, before)
		}

		beforeHash := hashPackedEntry(t, original, before)
		afterHash := hashPackedEntry(t, edited, after)
		if afterHash != beforeHash {
			t.Fatalf("Editor changed packed payload for %q: got %s, want %s", before.Path, afterHash, beforeHash)
		}
	}

	trailer, ok := edited.SHA1Trailer()
	if !ok || hex.EncodeToString(trailer[:]) != artifact.TrailerSHA1 {
		t.Fatalf("edited SHA1Trailer=(%x, %t), want %s", trailer, ok, artifact.TrailerSHA1)
	}
}

// hashPackedEntry computes a digest over stored bytes without decompressing the payload.
func hashPackedEntry(t *testing.T, reader *Reader, entry EntryInfo) string {
	t.Helper()

	digest := sha256.New()
	if _, err := reader.CopyPackedEntryInfoTo(entry, digest); err != nil {
		t.Fatalf("CopyPackedEntryInfoTo(%q): %v", entry.Path, err)
	}

	return hex.EncodeToString(digest.Sum(nil))
}

// assertCorpusHashMapsEqual reports missing, extra, or changed fixture content.
func assertCorpusHashMapsEqual(t *testing.T, got, want map[string]string, context string) {
	t.Helper()

	if len(got) != len(want) {
		t.Errorf("%s: file count=%d, want %d", context, len(got), len(want))
	}

	for path, wantHash := range want {
		if gotHash, ok := got[path]; !ok {
			t.Errorf("%s: missing %q", context, path)
		} else if gotHash != wantHash {
			t.Errorf("%s: %q SHA-256=%s, want %s", context, path, gotHash, wantHash)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			t.Errorf("%s: unexpected %q", context, path)
		}
	}
}

package pbo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	benchDefaultEntries    = 128
	benchLargeIndexEntries = 52536
)

var (
	// benchListSink prevents compiler elimination in list benchmark loops.
	benchListSink int
)

func BenchmarkOpenParse(b *testing.B) {
	path := createBenchPBO(b, benchDefaultEntries)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = r.Entries()
		_ = r.Close()
	}
}

func BenchmarkOpenParseLargeIndex(b *testing.B) {
	path := createBenchLargeIndexPBO(b, benchLargeIndexEntries)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}

		if len(r.Entries()) == 0 {
			b.Fatal("empty entries")
		}

		_ = r.Close()
	}
}

func BenchmarkExtract(b *testing.B) {
	benchmarkExtractWithSanitize(b, false)
}

func BenchmarkExtractSanitize(b *testing.B) {
	benchmarkExtractWithSanitize(b, true)
}

func BenchmarkListLargeIndex(b *testing.B) {
	path := createBenchLargeIndexPBO(b, benchLargeIndexEntries)
	r, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	entries := r.Entries()
	if len(entries) == 0 {
		b.Fatal("empty entries")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		total := 0
		for _, e := range entries {
			total += len(e.Path)
			total += int(e.DataSize)
			total += int(e.OriginalSize)
		}

		benchListSink = total
	}
}

// benchmarkExtractWithSanitize benchmarks full extract flow with optional path sanitization.
func benchmarkExtractWithSanitize(b *testing.B, sanitizeNames bool) {
	path := createBenchPBO(b, benchDefaultEntries)
	dir := b.TempDir()
	opts := ExtractOptions{
		MaxWorkers: 4,
		RawNames:   !sanitizeNames,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := Open(path)
		if err != nil {
			b.Fatal(err)
		}
		out := filepath.Join(dir, "ext", fmt.Sprintf("run%d", i))
		_ = os.MkdirAll(out, 0o755)
		err = r.Extract(context.Background(), out, opts)
		_ = r.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkComputeHashSetLargeIndex(b *testing.B) {
	path := createBenchLargeIndexPBO(b, benchLargeIndexEntries)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ComputeHashSet(path, SignVersionV3, GameTypeDayZ); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackNoCompress(b *testing.B) {
	payload := []byte("hello world")
	inputs := make([]Input, 20)
	for i := range inputs {
		inputs[i] = Input{
			Path: filepath.Join("dir", "file", fmt.Sprintf("f%d.txt", i)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
			SizeHint: int64(len(payload)),
		}
	}
	opts := PackOptions{}
	dir := b.TempDir()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("out%d.pbo", i))
		f, _ := os.Create(out)
		_, err := Pack(context.Background(), f, inputs, opts)
		_ = f.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackWithCompress(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 2000)
	inputs := make([]Input, 10)
	for i := range inputs {
		inputs[i] = Input{
			Path: filepath.Join("data", fmt.Sprintf("f%d.dat", i)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
			SizeHint: int64(len(data)),
		}
	}
	opts := PackOptions{Compress: includeRules("*")}
	dir := b.TempDir()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("out%d.pbo", i))
		f, _ := os.Create(out)
		_, err := Pack(context.Background(), f, inputs, opts)
		_ = f.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackWithCompressNoMatch(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 2000)
	inputs := make([]Input, 10)
	for i := range inputs {
		inputs[i] = Input{
			Path: filepath.Join("data", fmt.Sprintf("f%d.dat", i)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
			SizeHint: int64(len(data)),
		}
	}
	opts := PackOptions{Compress: includeRules("*.paa")}
	dir := b.TempDir()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("out%d.pbo", i))
		f, _ := os.Create(out)
		_, err := Pack(context.Background(), f, inputs, opts)
		_ = f.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPackAndHash(b *testing.B) {
	data := bytes.Repeat([]byte("x"), 2000)
	inputs := make([]Input, 10)
	for i := range inputs {
		inputs[i] = Input{
			Path: filepath.Join("data", fmt.Sprintf("f%d.c", i)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			},
			SizeHint: int64(len(data)),
		}
	}
	opts := PackOptions{Compress: includeRules("*.c")}
	dir := b.TempDir()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("out%d.pbo", i))
		f, _ := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		_, _, err := PackAndHash(context.Background(), f, inputs, opts, SignVersionV3, GameTypeDayZ)
		_ = f.Close()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEditAdd(b *testing.B) {
	template := createBenchPBO(b, 128)
	dir := b.TempDir()
	addPayload := bytes.Repeat([]byte("add"), 2048)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("edit-add-%d.pbo", i))
		if err := copyBenchFile(template, out); err != nil {
			b.Fatal(err)
		}

		editor, err := OpenEditor(out, EditOptions{
			PackOptions: PackOptions{
				Compress:        includeRules("*.txt"),
				MinCompressSize: 1,
			},
			BackupKeep: 0,
		})
		if err != nil {
			b.Fatal(err)
		}

		err = editor.Add(Input{
			Path: "bench/new_added.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(addPayload)), nil
			},
			SizeHint: int64(len(addPayload)),
		})
		if err != nil {
			b.Fatal(err)
		}

		if _, err := editor.Commit(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEditReplace(b *testing.B) {
	template := createBenchPBO(b, 128)
	dir := b.TempDir()
	replacePayload := bytes.Repeat([]byte("replace"), 2048)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("edit-replace-%d.pbo", i))
		if err := copyBenchFile(template, out); err != nil {
			b.Fatal(err)
		}

		editor, err := OpenEditor(out, EditOptions{
			PackOptions: PackOptions{
				Compress:        includeRules("*.txt"),
				MinCompressSize: 1,
			},
			BackupKeep: 0,
		})
		if err != nil {
			b.Fatal(err)
		}

		err = editor.Replace(Input{
			Path: "e/f0.txt",
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(replacePayload)), nil
			},
			SizeHint: int64(len(replacePayload)),
		})
		if err != nil {
			b.Fatal(err)
		}

		if _, err := editor.Commit(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEditDelete(b *testing.B) {
	template := createBenchPBO(b, 128)
	dir := b.TempDir()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := filepath.Join(dir, fmt.Sprintf("edit-delete-%d.pbo", i))
		if err := copyBenchFile(template, out); err != nil {
			b.Fatal(err)
		}

		editor, err := OpenEditor(out, EditOptions{BackupKeep: 0})
		if err != nil {
			b.Fatal(err)
		}

		if err := editor.Delete("e/f0.txt", "e/f1.txt", "e/f2.txt"); err != nil {
			b.Fatal(err)
		}

		if _, err := editor.Commit(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

// createBenchPBO builds a deterministic benchmark archive with fixed-size text entries.
func createBenchPBO(b *testing.B, numEntries int) string {
	dir := b.TempDir()
	out := filepath.Join(dir, "bench.pbo")
	inputs := make([]Input, numEntries)
	open := benchOpenBytes([]byte("content"))

	for i := range inputs {
		inputs[i] = Input{
			Path: filepath.Join("e", fmt.Sprintf("f%d.txt", i)),
			Open: open,
		}
	}

	f, err := os.Create(out)
	if err != nil {
		b.Fatal(err)
	}
	_, err = Pack(context.Background(), f, inputs, PackOptions{})
	if err != nil {
		_ = f.Close()
		b.Fatal(err)
	}
	_ = writeSHA1Trailer(out)
	_ = f.Close()
	return out
}

// createBenchLargeIndexPBO builds a large index fixture with mixed extensions.
func createBenchLargeIndexPBO(b *testing.B, numEntries int) string {
	dir := b.TempDir()
	out := filepath.Join(dir, "bench-large.pbo")
	inputs := make([]Input, numEntries)
	open := benchOpenBytes(bytes.Repeat([]byte("x"), 96))

	for i := range inputs {
		inputs[i] = Input{
			Path:     benchmarkLargePath(i),
			Open:     open,
			SizeHint: 96,
		}
	}
	f, err := os.Create(out)
	if err != nil {
		b.Fatal(err)
	}
	_, err = Pack(context.Background(), f, inputs, PackOptions{})
	if err != nil {
		_ = f.Close()
		b.Fatal(err)
	}
	_ = writeSHA1Trailer(out)
	_ = f.Close()
	return out
}

// benchmarkLargePath returns deterministic long-ish paths for index-heavy benchmarks.
func benchmarkLargePath(i int) string {
	exts := [...]string{"c", "cfg", "hpp", "h", "bikb", "ext", "inc", "paa", "p3d", "rtm", "txt"}
	ext := exts[i%len(exts)]

	return filepath.Join(
		fmt.Sprintf("grp_%03d", i%173),
		fmt.Sprintf("pack_%03d", (i/173)%211),
		fmt.Sprintf("layer_%03d", (i/370)%257),
		fmt.Sprintf("entry_%05d_%08x.%s", i, i*2654435761, ext),
	)
}

// benchOpenBytes returns a reusable opener that creates a fresh reader for each call.
func benchOpenBytes(data []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
}

// copyBenchFile copies fixture file to destination path.
func copyBenchFile(src string, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0o600)
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/woozymasta/pbo"
	"github.com/woozymasta/pbo/inspect"
)

func exampleInput(path, content string) pbo.Input {
	return pbo.Input{
		Path: path,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content)), nil
		},
	}
}

func exampleArchive() (string, func(), error) {
	dir, err := os.MkdirTemp("", "pbo-example-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "example.pbo")
	_, err = pbo.PackFile(context.Background(), path, []pbo.Input{
		exampleInput("CON.txt", "reserved name"),
		exampleInput("data/a:b.txt", "payload"),
		exampleInput("scripts/main.c", "hello"),
	}, pbo.PackOptions{
		Headers: []pbo.HeaderPair{{Key: "prefix", Value: "demo"}},
	})
	if err != nil {
		cleanup()
		return "", nil, err
	}

	return path, cleanup, nil
}

func ExampleOpen() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()

	data, err := r.ReadEntry("scripts/main.c")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(data))

	// Output:
	// hello
}

func ExampleListEntries() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	headers, err := pbo.ReadHeaders(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	entries, err := pbo.ListEntries(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, header := range headers {
		if header.Key == "prefix" {
			fmt.Printf("%s=%s\n", header.Key, header.Value)
		}
	}
	for _, entry := range entries {
		fmt.Println(entry.Path)
	}

	// Output:
	// prefix=demo
	// CON.txt
	// data\a:b.txt
	// scripts\main.c
}

func ExampleSelect() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()

	selection, err := inspect.Select(context.Background(), r, inspect.Options{
		PathPrefix: "data",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	view, err := inspect.View(selection, inspect.ViewOptions{FilesystemSafe: true})
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, entry := range view {
		stream, err := r.OpenEntryInfo(entry.Raw)
		if err != nil {
			fmt.Println(err)
			return
		}
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(entry.DisplayPath)
		fmt.Println(string(data))
	}

	// Output:
	// data/a_b.txt
	// payload
}

func ExampleSelection_Entries_emptySafeForExtract() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()

	selection, err := inspect.Select(context.Background(), r, inspect.Options{
		PathPrefix: "missing",
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	entries := selection.Entries()
	destination, err := os.MkdirTemp("", "pbo-empty-selection-example-")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = os.RemoveAll(destination) }()

	if err := r.Extract(context.Background(), destination, pbo.ExtractOptions{
		Entries: entries,
	}); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("nil=%t count=%d\n", entries == nil, len(entries))

	// Output:
	// nil=false count=0
}

func ExampleReader_TrailerStatus() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()

	fmt.Println(r.TrailerStatus())

	// Output:
	// candidate
}

func ExampleReader_Extract() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()

	dir, err := os.MkdirTemp("", "pbo-extract-example-")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := r.Extract(context.Background(), dir, pbo.ExtractOptions{MaxWorkers: 2}); err != nil {
		fmt.Println(err)
		return
	}

	data, err := os.ReadFile(filepath.Join(dir, "scripts", "main.c"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(data))

	// Output:
	// hello
}

func ExamplePackFile() {
	dir, err := os.MkdirTemp("", "pbo-pack-example-")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "new.pbo")
	result, err := pbo.PackFile(context.Background(), path, []pbo.Input{
		exampleInput("readme.txt", "hello"),
	}, pbo.PackOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result.WrittenEntries)

	// Output:
	// 1
}

func ExampleOpenEditor() {
	path, cleanup, err := exampleArchive()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cleanup()

	editor, err := pbo.OpenEditor(path, pbo.EditOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := editor.Replace(exampleInput("scripts/main.c", "updated")); err != nil {
		fmt.Println(err)
		return
	}
	if _, err := editor.Commit(context.Background()); err != nil {
		fmt.Println(err)
		return
	}

	r, err := pbo.Open(path)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() { _ = r.Close() }()
	data, err := r.ReadEntry("scripts/main.c")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(data))

	// Output:
	// updated
}

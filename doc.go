// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

/*
Package pbo provides read, extract, pack, hash, and edit operations for
PBO (Packed Bank of files) archives. It is designed for streaming workflows:
packing accepts caller-provided streams (Input.Open), and reading/extracting
works without loading full archive payload into memory.

Compression rules (summary):
  - path decision must include entry via PackOptions.Compress rules;
  - final entry size must be within [MinCompressSize, MaxCompressSize];
  - known-size inputs use in-memory compression path (bounded by MaxCompressSize);
  - unknown-size inputs are streamed raw (no temp-file fallback);
  - compression is written only when result is smaller than source.

# Reading

Open a PBO and list or read entries:

	r, err := pbo.Open("addon.pbo")
	if err != nil {
	    return err
	}
	defer r.Close()
	for _, e := range r.Entries() {
	    data, _ := r.ReadEntry(e.Path)
	    // use data
	}

For metadata-only scans, use fast helpers without creating a full reader:

	headers, err := pbo.ReadHeaders("addon.pbo")
	if err != nil {
	    return err
	}
	entries, err := pbo.ListEntries("addon.pbo")
	if err != nil {
	    return err
	}
	_, _ = headers, entries

For filesystem-safe listing names:

	entries, err := pbo.ListEntriesWithOptions("addon.pbo", pbo.ReaderOptions{
	    SanitizeNames: true,
	})
	if err != nil {
	    return err
	}
	_ = entries

For noisy or obfuscated archives, combine entry filters:

	r, err := pbo.OpenWithOptions("addon.pbo", pbo.ReaderOptions{
	    MinEntryOriginalSize: 12,
	    MinEntryDataSize:     0,
	    EntryPathPrefix:      "scripts/4_world",
	    FilterASCIIOnly:      false,
	    SanitizeControlChars: true,
	    SanitizeNames:        true,
	})
	if err != nil {
	    return err
	}
	defer r.Close()

For archives with meaningful non-zero index offsets, use compatibility mode:

	r, err := pbo.OpenWithOptions("addon.pbo", pbo.ReaderOptions{
	    OffsetMode: pbo.OffsetModeStoredCompat,
	})
	if err != nil {
	    return err
	}
	defer r.Close()

# Extracting

Extract all entries to a directory (parallel workers):

	if err := r.Extract(ctx, "out/", pbo.ExtractOptions{MaxWorkers: 4}); err != nil {
	    return err
	}

Path sanitization is enabled by default during extraction.
Disable it explicitly when raw names are required:

	if err := r.Extract(ctx, "out/", pbo.ExtractOptions{
	    MaxWorkers: 4,
	    RawNames:   true,
	}); err != nil {
	    return err
	}

# Packing

Pack from stream-oriented inputs (order is deterministic by path):
examples below use github.com/woozymasta/pathrules for compression filters:

	inputs := []pbo.Input{
	    {Path: "config.cpp", Open: func() (io.ReadCloser, error) { return os.Open("src/config.cpp") }},
	}
	res, err := pbo.Pack(ctx, outFile, inputs, pbo.PackOptions{
	    Headers: []pbo.HeaderPair{{Key: "prefix", Value: "myaddon"}},
	    // Empty rule set means no compression.
	    Compress: []pathrules.Rule{
	        {Action: pathrules.ActionInclude, Pattern: "*.rvmat"},
	        {Action: pathrules.ActionInclude, Pattern: "textures/**"},
	    },
	    CompressMatcherOptions: pathrules.MatcherOptions{
	        CaseInsensitive: true,
	        DefaultAction:   pathrules.ActionExclude,
	    },
	    OnEntryDone: func(entry pbo.PackEntryProgress) {
	        // progress callback per written entry
	    },
	})
	_ = res.CompressedEntries
	_ = res.SkippedCompressionEntries

Use default mode for restricted environments where only output path is
writable (unknown-size candidates remain raw):

	res, err := pbo.Pack(ctx, outFile, inputs, pbo.PackOptions{
	    Compress: []pathrules.Rule{
	        {Action: pathrules.ActionInclude, Pattern: "*"},
	    },
	})

To write to a path and append the SHA1 trailer:

	res, err := pbo.PackFile(ctx, "addon.pbo", inputs, opts)

To pack and calculate signature hash set in one flow:

	res, hs, err := pbo.PackAndHashFile(
	    ctx,
	    "addon.pbo",
	    inputs,
	    opts,
	    pbo.SignVersionV3,
	    pbo.GameTypeDayZ,
	)
	_, _ = res, hs

To edit existing archive in one transaction:

	editor, err := pbo.OpenEditor("addon.pbo", pbo.EditOptions{
	    PackOptions: pbo.PackOptions{
	        Compress: []pathrules.Rule{
	            {Action: pathrules.ActionInclude, Pattern: "*.txt"},
	        },
	        CompressMatcherOptions: pathrules.MatcherOptions{
	            CaseInsensitive: true,
	            DefaultAction:   pathrules.ActionExclude,
	        },
	    },
	    BackupKeep:  1,
	})
	if err != nil {
	    return err
	}
	if err := editor.Replace(pbo.Input{
	    Path: "scripts/main.c",
	    Open: func() (io.ReadCloser, error) { return os.Open("scripts/main.c") },
	}); err != nil {
	    return err
	}
	if _, err := editor.Commit(ctx); err != nil {
	    return err
	}
*/
package pbo

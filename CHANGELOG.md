<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][],
and this project adheres to [Semantic Versioning][].

<!--
## Unreleased

### Added
### Changed
### Removed
-->

## [0.3.0][] - 2026-07-01

### Added

* `EntriesView` returns the internal entry slice without copying;
  zero-alloc alternative to `Entries()` for read-only listing and polling.
* `RangeEntries` iterates entries with early-exit support, also zero-alloc.
* `OpenPackedEntryInfo` and `CopyPackedEntryInfoTo` expose raw
  (compressed, as-stored) entry bytes without decompression,
  for selective replace and hash/debug tooling.
* `LargeWriteBuffer` constant (16 MiB) as explicit opt-in
  for bulk sequential packing workloads.
* `CopyEntryTo` and `CopyEntryInfoTo` -
  push-model entry read API that decompresses directly into an `io.Writer`
  without spawning a goroutine or pipe.
  Suitable for `http.ResponseWriter` and `os.File` consumers.
* Fuzz targets for the PBO parser, entry reader, and extract path
  `FuzzNewReaderFromReaderAt`, `FuzzOpenEntry`, `FuzzExtract`.

### Changed

* Pack index is now written as a single pre-built block via `WriteAt`
  (or `Seek`+`Write` fallback) instead of N separate seek+patch calls per entry.
  Reduces system call count from 2N to 1 for large archives.
* `Editor.Commit` no longer reopens the output file to append the SHA1 trailer;
  it is written inline via `WriteAt`, matching `PackFile` behavior.
* `PackFile` and `PackAndHashFile` no longer close
  and reopen the output file to append the SHA1 trailer;
  it is written inline via `WriteAt`.
* `PackAndHash` and `PackAndHashFile` compute `hash1` from in-memory
  header and index sections, re-reading only the payload region from disk.
  Sign-eligible payload bytes are teed to the file-hash during the write pass,
  eliminating a second file read for `fileHash`.
* Archive entry paths from `filepath.Walk`/`filepath.Join` on Windows are
  now detected as already canonical and skip the full normalization chain
  (zero allocations for the common case).
  Case-insensitive dedup uses `asciiLower` instead of `strings.ToLower`
  to avoid allocations for already-lowercase paths.
* `estimateEntryCapacity` cap raised from 8192 to 65536
  to avoid multiple slice growths when reading large-index PBOs.
* `DefaultWriteBuffer` reduced from 16 MiB to 4 MiB
  to lower pool memory pressure for long-lived daemons;
  use `LargeWriteBuffer` to restore the previous behavior.
* Extraction no longer spawns a goroutine and pipe per compressed entry;
  decompression writes directly into the destination file
  using the worker's existing copy buffer.

### Fixed

* `applySealedTransformToWriteSeeker` no longer asserts
  `io.ReaderAt`/`io.WriterAt` when the sealed key is nil or disabled,
  which previously caused `Pack` to fail with a plain `io.WriteSeeker` output.

[0.3.0]: https://github.com/WoozyMasta/pbo/compare/v0.2.0...v0.3.0

## [0.2.0][] - 2026-04-04

### Added

* Optional sealed archive mode for read/write flows via package options.

### Changed

* Entry lookup for `OpenEntry` now uses a lazy normalized-path index instead
  of linear scan.
* Extraction is now fail-fast by default and can be switched to
  continue-on-error mode via `ExtractOptions.ContinueOnError`.

[0.2.0]: https://github.com/WoozyMasta/pbo/compare/v0.1.1...v0.2.0

## [0.1.1][] - 2026-02-25

### Added

* `ReaderOptions.MinEntryOriginalSize`
  filter to drop tiny entries by logical original size
  (`OriginalSize`, fallback to `DataSize`).
* `ReaderOptions.MinEntryDataSize`
  filter to drop entries by packed payload size.
* `ReaderOptions.EntryPathPrefix`
  filter to keep only one normalized path subtree (or exact file path).
* `ReaderOptions.FilterASCIIOnly`
  filter to keep only ASCII-only entry paths in obfuscated archives.
* `ReaderOptions.SanitizeControlChars`
  filter to rewrite control/format runes in entry paths for safe output.

### Changed

* Path sanitization is now more resilient on obfuscated/mangled names
  (including `.{GUID}` Windows namespace suffix normalization) and keeps
  deterministic unique output names.

[0.1.1]: https://github.com/WoozyMasta/pbo/compare/v0.1.0...v0.1.1

## [0.1.0][] - 2026-02-21

### Added

* First public release

[0.1.0]: https://github.com/WoozyMasta/pbo/v0.1.0

<!--links-->
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

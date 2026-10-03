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

## Unreleased

### Added

* Added generic and typed PBO property accessors,
  filtered entry views through `Reader.EntriesWithOptions`,
  and editor operations for targeting duplicate entries
  by index and changing header properties.

### Changed

* `Reader.Entries`, `EntriesView`, path lookup,
  and default extraction use raw archive paths.
  Derived filtering and sanitization are explicit
  through `Reader.EntriesWithOptions`;
  duplicate entries stay in source order and path lookup returns first match.
* Editor preserves untouched entries' source order, raw paths, metadata,
  and packed payloads. New entries are appended;
  path-based replacement and deletion return an ambiguity error
  when a path matches multiple entries.
* Packing resets truncatable outputs and rejects non-empty outputs
  that cannot be truncated.
  File-based packing replaces the destination
  only after the complete archive and SHA1 trailer have been written.
* Path matching normalizes separators and folds ASCII case.
  Sanitized Unicode path segments remain valid UTF-8 when shortened.
* Parser limits now bound header fields, properties,
  entry names, and index records.
  Compression candidates that exceed `MaxCompressSize`
  fall back to raw streaming.
* Header-only reads of sealed archives skip payload reads.
  In `TrailerModeAuto`, they do not verify the trailer;
  use a full `Reader` and `SHA1Trailer()` when integrity must be checked.
* Trailer detection uses the resolved payload boundary,
  and `SHA1Trailer()` returns a digest only after verification.

### Fixed

* Writer rejects malformed NUL-terminated fields
  before writing or truncating output.
* `CopyEntryTo` and `CopyEntryInfoTo` report decompressed bytes
  written for compressed entries.

### Security

* Extraction confines filesystem access to `os.Root`,
  preventing archive paths and symlinks from escaping the destination.

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

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

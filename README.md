# pbo

[pbo][pbo] is a Go library for working with PBO archives used by Arma and DayZ.
It reads archive metadata and payloads, creates and edits archives,
and extracts their contents.

## When to use it

Use this module in tools that inspect game archives, build addon PBOs,
update existing archives, or extract files for analysis.
It handles the PBO container format; source transformations
and addon build pipelines remain the caller's responsibility.

## Installation

Add the module to your project with:

```sh
go get github.com/woozymasta/pbo@latest
```

## What it provides

* Read headers and entry indexes without loading payload data.
* Read packed or decompressed entries, including streaming access.
* Pack entries from files or caller-provided streams in deterministic order.
* Optionally compress selected entries with LZSS and calculate signature hashes.
* Edit archives while preserving untouched entries and their stored data.
* Extract entries with sanitized paths and destination-root confinement.

The library also supports duplicate entry paths, and bounded metadata parsing.
See the package documentation for the exact behavior and options.

<!-- links -->

[pbo]: https://pkg.go.dev/github.com/woozymasta/pbo

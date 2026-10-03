// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

/*
Package pbo reads, writes, extracts, signs,
and edits PBO archives used by Arma and DayZ tools.

Archive metadata is parsed separately from payload data.
Opening an archive reads its headers and entry index;
payload bytes are accessed only when an entry is read or extracted.
[ReadHeaders] and [ListEntries] provide
metadata-only access without creating a [Reader].

# Reading

[Open] reads an archive from a file, while [NewReaderFromReaderAt] supports
files, memory buffers, and other random-access sources.
A [Reader] provides ordered headers and entries, path lookup,
and access to unpacked or packed payloads.
Use [ReadEntry] to load an entry into memory,
or [OpenEntry] and [CopyEntryTo] for streaming access.

Entries retain their raw archive paths, and duplicate paths remain in source order.
Lookup normalizes separators, folds ASCII case, and selects the first matching entry.
[Reader.EntriesWithOptions] creates a separate filtered
or sanitized view without changing the reader's raw entries.
[Reader.EntriesView] and [Reader.RangeEntries]
provide lower-allocation ways to enumerate entry metadata.

# Extraction

[Reader.Extract] extracts all entries by default and sanitizes output names.
Filesystem access stays confined to the destination root
even when [ExtractOptions.RawNames] disables path sanitization.
Extraction options also control entry selection, concurrency,
overwrite behavior, and error handling.

# Writing and editing

[Pack] and [PackFile] create archives from caller-provided streams through [Input.Open].
Entry order is deterministic;
optional LZSS compression is selected with [PackOptions.Compress].
With no [PackOptions.CompressRules],
the automatic profile selects known compressible formats
from each stream's extension and a bounded content prefix.
Explicit rules replace the profile.
The profile also applies measured per-format size ranges;
non-zero [PackOptions.MinCompressSize] and [PackOptions.MaxCompressSize]
further narrow those ranges.
Zero minimum uses profile defaults, or 512 bytes with explicit rules.
Compressed output is kept only when it is smaller than the source.
[PackOptions.MaxCompressSize] bounds compression buffering,
with larger entries written without compression.

[Pack] starts at offset zero and resets outputs that support truncation.
Other outputs must be empty and positioned at zero.
File-based pack operations stage the complete archive
before replacing the destination and append a SHA1 trailer.

[OpenEditor] stages changes for one archive rewrite with [Editor.Commit].
The editor preserves untouched entries' raw paths, metadata, packed payloads,
and source order; added entries are appended.
File-based edits can retain and rotate backups.

# Headers and signatures

Headers can be read in order without parsing the entry index.
[Reader.Property] and typed accessors such as
[Reader.Prefix], [Reader.Version], and [Reader.FSShadowing] provide property access.
Pack options support matching generic and typed setters.

[ComputeHashSet], [PackAndHash], and [PackAndHashFile]
calculate signature hashes for supported versions and game types.
[Reader.SHA1Trailer] reports a trailer only after verifying it.

# Resource limits

[ReaderLimits] bounds header sections, fields, properties, entry names, and index records.
Zero-valued limits use defensive defaults;
callers processing unusual archives can raise individual limits.
*/
package pbo

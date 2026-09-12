// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

/*
Package pbo reads, writes, extracts, signs, and edits PBO archives used by Arma and DayZ tools.

The package handles archive metadata separately from payload data.
Opening an archive parses its headers and entry index;
payload bytes are read only when an entry is accessed or extracted.
[ReadHeaders] and [ListEntries] provide metadata-only operations
for callers that do not need a [Reader].

# Reading

[Open] reads an archive from a file.
[NewReaderFromReaderAt] supports files, memory buffers, and other random-access sources.
[Reader] exposes ordered headers and entry metadata, lookup by archive path,
and access to unpacked or packed entry bytes.
[ReadEntry] returns the complete unpacked entry in memory;
[OpenEntry] and [CopyEntryTo] support streaming access.
The reader can also decode sealed archives when given a [SealedKey].
[ReaderOptions] controls decoding, trailer handling,
offset interpretation, and parser resource limits.

Entry paths returned by [Reader.Entries] preserve their raw archive identity.
Lookup normalizes path separators and folds ASCII case;
non-ASCII bytes are preserved.
Duplicate paths remain present in the entry list,
while lookup selects the first matching entry.

[Reader.EntriesWithOptions] builds a separate filtered or sanitized view.
Filtering and path rewriting do not change the reader's raw entries.
Each [EntryInfo] retains its payload offset,
so [Reader.OpenEntryInfo] and [Reader.CopyEntryInfoTo] can access
the corresponding source entry even when the view rewrites its displayed path.
[Reader.EntriesView] and [Reader.RangeEntries] provide lower-allocation ways
to enumerate raw metadata.

# Extraction

[Reader.Extract] extracts all raw entries by default,
or a selected list passed through [ExtractOptions.Entries].
Output names are sanitized by default.
Extraction confines filesystem operations to the destination root
and limits the number of active workers.
Callers can select overwrite behavior and choose whether processing stops at the first error.

# Writing and editing

[Pack] and [PackFile] write entries from caller-provided streams through [Input.Open].
Entry order is deterministic. Compression candidates are chosen by path rules
and stored compressed only when compression reduces their size.
[PackOptions.MaxCompressSize] bounds candidate buffering;
larger inputs are written without compression.
[PackFile] appends a SHA1 trailer.

[OpenEditor] stages additions, replacements, and deletions,
then applies them as one archive rewrite with [Editor.Commit].
File-based edits can retain and rotate backup generations.
The editor preserves untouched entries' raw paths,
metadata, packed payload bytes, and source order;
added entries are appended in staging order.
Path-based replacement and deletion return [ErrAmbiguousEntryPath]
when a path identifies multiple entries.
[Editor.ReplaceAt] and [Editor.DeleteAt] address a specific source entry
by its zero-based index in the original archive.

Source properties are retained
while [PackOptions.Headers] and [Editor.SetProperty] apply named overrides.
[Editor.DeleteProperty] removes a named property,
and [Editor.ClearProperties] explicitly removes all properties.

# Headers and signatures

PBO headers are available in their original order and can be read
without parsing the entry index.
[Reader.Property], [Reader.Prefix], [Reader.Version], and [Reader.FSShadowing]
provide access to common properties.
Pack options support the same property names and typed setters.

[Reader.SHA1Trailer] reports the optional trailer only after verifying it.
[ComputeHashSet], [PackAndHash], and [PackAndHashFile]
calculate signature hashes for supported signature versions and game types.

# Resource limits

[ReaderLimits] bounds header sections, individual fields,
property counts, entry-name lengths, and index record counts.
Zero-valued limits use defensive defaults;
callers processing unusual archives can raise individual limits.
*/
package pbo

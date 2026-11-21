// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

/*
Package inspect selects PBO entries by metadata and bounded payload probes,
then builds display views while keeping raw entry identity.

Payload reads are opt-in and bounded per entry;
unknown, incomplete, or failed checks keep their entries
unless an explicit aggressive filter applies.

Small compressed entries are decoded only when ScanCompressedSmall is enabled.

The default packed and decoded limits are 4 KiB and 1 KiB per entry;
callers may raise either to the 64 MiB hard cap.

Blank scans default to 1 KiB and have the same hard cap.

Match and Entries preserve raw metadata;
[View] returns separate display paths, with optional filesystem-safe sanitation after selection.

Use [Selection.Entries] with pbo.ExtractOptions.Entries for explicit extraction.
*/
package inspect

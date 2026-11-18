// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

import "testing"

// mustUint32ForTest converts a bounded fixture value to a PBO uint32 field.
func mustUint32ForTest(t testing.TB, value int64) uint32 {
	t.Helper()

	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		t.Fatalf("fixture value %d does not fit in uint32", value)
	}

	return uint32(value) //nolint:gosec // The bounds check above proves the conversion is safe.
}

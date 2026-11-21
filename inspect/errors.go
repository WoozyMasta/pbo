// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package inspect

import "errors"

// Sentinel errors returned by inspect operations.
var (
	// ErrNilContext indicates Select received a nil context.
	ErrNilContext = errors.New("inspect context is nil")
	// ErrInvalidOptions indicates an incompatible selection range.
	ErrInvalidOptions = errors.New("invalid inspect options")
)

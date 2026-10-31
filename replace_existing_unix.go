// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

//go:build unix

package pbo

import (
	"errors"
	"fmt"
	"os"
)

// replaceExistingOutputFile uses same-directory rename for atomic replacement.
func replaceExistingOutputFile(tempPath string, outPath string, backupPath string) error {
	if backupPath != "" {
		if err := os.Link(outPath, backupPath); err != nil {
			return fmt.Errorf("create previous PBO backup link: %w", err)
		}
	}

	if err := os.Rename(tempPath, outPath); err != nil {
		if backupPath != "" {
			return errors.Join(fmt.Errorf("install replacement PBO: %w", err), os.Remove(backupPath))
		}

		return fmt.Errorf("install replacement PBO: %w", err)
	}

	return nil
}

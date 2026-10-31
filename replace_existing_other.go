// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

//go:build !unix && !windows

package pbo

import (
	"fmt"
	"os"
	"path/filepath"
)

// replaceExistingOutputFile uses a recoverable rename sequence on other platforms.
func replaceExistingOutputFile(tempPath string, outPath string, backupPath string) error {
	removeBackup := false
	if backupPath == "" {
		backupFile, err := os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".bak-*")
		if err != nil {
			return fmt.Errorf("reserve replacement backup: %w", err)
		}

		backupPath = backupFile.Name()
		if err := backupFile.Close(); err != nil {
			_ = os.Remove(backupPath)
			return fmt.Errorf("close replacement backup placeholder: %w", err)
		}

		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("remove replacement backup placeholder: %w", err)
		}

		removeBackup = true
	}

	if err := os.Rename(outPath, backupPath); err != nil {
		return fmt.Errorf("move previous PBO aside: %w", err)
	}

	if err := os.Rename(tempPath, outPath); err != nil {
		if restoreErr := os.Rename(backupPath, outPath); restoreErr != nil {
			return fmt.Errorf("install replacement PBO: %w; restore previous PBO from %q: %v", err, backupPath, restoreErr)
		}

		return fmt.Errorf("install replacement PBO: %w", err)
	}

	if removeBackup {
		if err := os.Remove(backupPath); err != nil {
			return fmt.Errorf("remove temporary replacement backup: %w", err)
		}
	}

	return nil
}

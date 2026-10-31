// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

//go:build windows

package pbo

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	// replaceFileProc is the Windows API used to install a prepared replacement.
	replaceFileProc = syscall.NewLazyDLL("kernel32.dll").NewProc("ReplaceFileW")
)

// replaceExistingOutputFile replaces the target and can save its previous version.
func replaceExistingOutputFile(tempPath string, outPath string, backupPath string) error {
	target, err := syscall.UTF16PtrFromString(outPath)
	if err != nil {
		return fmt.Errorf("encode target path: %w", err)
	}

	replacement, err := syscall.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("encode replacement path: %w", err)
	}

	var backup *uint16
	if backupPath != "" {
		backup, err = syscall.UTF16PtrFromString(backupPath)
		if err != nil {
			return fmt.Errorf("encode backup path: %w", err)
		}
	}

	result, _, callErr := replaceFileProc.Call(
		uintptr(unsafe.Pointer(target)),
		uintptr(unsafe.Pointer(replacement)),
		uintptr(unsafe.Pointer(backup)),
		0, 0, 0,
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}

		return fmt.Errorf("ReplaceFileW: %w", callErr)
	}

	return nil
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WoozyMasta
// Source: github.com/woozymasta/pbo

package pbo

// SignVersion is PBO signature hash policy version.
type SignVersion uint32

// Supported signature hash policy versions.
const (
	// SignVersionV2 is the legacy version of PBO signature hash policy.
	SignVersionV2 SignVersion = 2
	// SignVersionV3 is the current version of PBO signature hash policy.
	SignVersionV3 SignVersion = 3
)

// GameType selects the game-specific file hash policy for v2 and v3 signatures.
type GameType string

// Supported game types for signature hash policies.
const (
	// GameTypeArma is the game type for Arma 3.
	GameTypeArma GameType = "arma"
	// GameTypeDayZ is the game type for DayZ.
	GameTypeDayZ GameType = "dayz"
)

// normalizeGameType returns ASCII lower-cased game type.
func normalizeGameType(gameType GameType) GameType {
	return GameType(asciiLower(string(gameType)))
}

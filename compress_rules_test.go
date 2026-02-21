package pbo

import (
	"strings"

	"github.com/woozymasta/pathrules"
)

// includeRules builds include rules from raw patterns for concise test setup.
func includeRules(patterns ...string) []pathrules.Rule {
	rules := make([]pathrules.Rule, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		rules = append(rules, pathrules.Rule{
			Action:  pathrules.ActionInclude,
			Pattern: pattern,
		})
	}

	return rules
}

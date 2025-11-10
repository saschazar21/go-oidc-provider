package utils

import "strings"

func SanitizeString(input string) string {
	trimmed := input
	trimmed = strings.TrimSpace(trimmed)
	trimmed = strings.ReplaceAll(trimmed, "\n", "")
	trimmed = strings.ReplaceAll(trimmed, "\r", "")
	return trimmed
}

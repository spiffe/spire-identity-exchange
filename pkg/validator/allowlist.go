package validator

import "strings"

// IsValueAllowed checks if a value matches any of the allowed patterns.
// Supports wildcard suffix matching (e.g., "my-org/*" matches "my-org/any-repo").
func IsValueAllowed(value string, allowedValues []string) bool {
	for _, av := range allowedValues {
		if strings.HasSuffix(av, "*") {
			pattern := strings.TrimSuffix(av, "*")
			if strings.HasPrefix(value, pattern) {
				return true
			}
		} else if value == av {
			return true
		}
	}
	return false
}

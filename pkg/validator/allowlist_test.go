package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValueAllowed(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		allowed  []string
		expected bool
	}{
		{
			name:     "exact_match",
			value:    "my-group/my-project",
			allowed:  []string{"my-group/my-project"},
			expected: true,
		},
		{
			name:     "no_match",
			value:    "my-group/my-project",
			allowed:  []string{"other-group/other-project"},
			expected: false,
		},
		{
			name:     "wildcard_suffix",
			value:    "my-group/my-project",
			allowed:  []string{"my-group/*"},
			expected: true,
		},
		{
			name:     "wildcard_no_match",
			value:    "other-group/my-project",
			allowed:  []string{"my-group/*"},
			expected: false,
		},
		{
			name:     "multiple_allowed",
			value:    "group-b/repo",
			allowed:  []string{"group-a/*", "group-b/*"},
			expected: true,
		},
		{
			name:     "empty_value",
			value:    "",
			allowed:  []string{"my-group/*"},
			expected: false,
		},
		{
			name:     "empty_allowed_list",
			value:    "my-group/my-project",
			allowed:  []string{},
			expected: false,
		},
		{
			name:     "star_only_wildcard",
			value:    "anything",
			allowed:  []string{"*"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValueAllowed(tt.value, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

package utils

import (
	"strings"
	"testing"
	"text/template"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetStringClaim(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		key      string
		expected string
	}{
		{
			name: "string_value_present",
			claims: map[string]interface{}{
				"key": "value",
			},
			key:      "key",
			expected: "value",
		},
		{
			name: "key_not_present",
			claims: map[string]interface{}{
				"other": "value",
			},
			key:      "key",
			expected: "",
		},
		{
			name: "non_string_value",
			claims: map[string]interface{}{
				"key": 12345,
			},
			key:      "key",
			expected: "",
		},
		{
			name: "nil_value",
			claims: map[string]interface{}{
				"key": nil,
			},
			key:      "key",
			expected: "",
		},
		{
			name:     "empty_claims",
			claims:   map[string]interface{}{},
			key:      "key",
			expected: "",
		},
		{
			name:     "nil_claims",
			claims:   nil,
			key:      "key",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetStringClaim(tt.claims, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValueAllowed(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		allowedValues []string
		expected      bool
	}{
		{
			name:          "exact_match",
			value:         "test-org/test-repo",
			allowedValues: []string{"test-org/test-repo", "other-org/other-repo"},
			expected:      true,
		},
		{
			name:          "wildcard_match",
			value:         "test-org/test-repo",
			allowedValues: []string{"test-org/*"},
			expected:      true,
		},
		{
			name:          "wildcard_no_match",
			value:         "other-org/test-repo",
			allowedValues: []string{"test-org/*"},
			expected:      false,
		},
		{
			name:          "no_match",
			value:         "test-org/test-repo",
			allowedValues: []string{"other-org/other-repo"},
			expected:      false,
		},
		{
			name:          "empty_value",
			value:         "",
			allowedValues: []string{"test-org/*"},
			expected:      false,
		},
		{
			name:          "empty_allowed_values",
			value:         "test-org/test-repo",
			allowedValues: []string{},
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValueAllowed(tt.value, tt.allowedValues)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeForSPIFFE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple_string",
			input:    "test-repo",
			expected: "test-repo",
		},
		{
			name:     "uppercase_to_lowercase",
			input:    "Test-Repo",
			expected: "test-repo",
		},
		{
			name:     "underscore_to_dash",
			input:    "test_repo",
			expected: "test-repo",
		},
		{
			name:     "multiple_dashes_collapsed",
			input:    "test___repo",
			expected: "test-repo",
		},
		{
			name:     "leading_and_trailing_dashes_removed",
			input:    "_test-repo_",
			expected: "test-repo",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
		},
		{
			name:     "max_length_exceeded",
			input:    strings.Repeat("a", 300),
			expected: strings.Repeat("a", 255),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForSPIFFE(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateSPIFFEID(t *testing.T) {
	tests := []struct {
		name            string
		rawClaims       map[string]interface{}
		templateStr     string
		trustDomain     string
		expectedPattern string
		expectError     bool
		errorContains   string
	}{
		{
			name: "valid_spiffe_id_with_template",
			rawClaims: map[string]interface{}{
				"repository": "test-org/test-repo",
				"ref":        "refs/heads/main",
			},
			templateStr:     "spiffe://{{.trust_domain}}/github/{{.org}}/{{.repository}}",
			trustDomain:     "example.com",
			expectedPattern: "spiffe://example.com/github/test-org/test-repo",
			expectError:     false,
		},
		{
			name: "template_without_spiffe_scheme",
			rawClaims: map[string]interface{}{
				"repository": "test-org/test-repo",
			},
			templateStr:   "github/{{.org}}/{{.repository}}",
			trustDomain:   "example.com",
			expectError:   true,
		},
		{
			name:          "nil_template",
			rawClaims:     map[string]interface{}{},
			templateStr:   "",
			trustDomain:   "example.com",
			expectError:   true,
			errorContains: "SPIFFE ID template is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tmpl *template.Template
			var err error

			if tt.templateStr != "" {
				tmpl, err = template.New("test").Parse(tt.templateStr)
				require.NoError(t, err)
			}

			result, err := GenerateSPIFFEID(tt.rawClaims, tmpl, tt.trustDomain)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Equal(t, spiffeid.ID{}, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedPattern, result.String())
			}
		})
	}
}

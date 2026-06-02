package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config_with_namespace_paths",
			cfg: Config{
				Audiences:             []string{"test-aud"},
				AllowedNamespacePaths: []string{"my-group"},
				AllowHTTP:             true,
				IssuerURL:             "http://localhost",
			},
			expectErr: false,
		},
		{
			name: "valid_config_with_project_paths",
			cfg: Config{
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-group/my-project"},
				AllowHTTP:           true,
				IssuerURL:           "http://localhost",
			},
			expectErr: false,
		},
		{
			name: "default_issuer",
			cfg: Config{
				Audiences:             []string{"test-aud"},
				AllowedNamespacePaths: []string{"my-group"},
			},
			expectErr: false,
		},
		{
			name: "no_allowlists",
			cfg: Config{
				Audiences: []string{"test-aud"},
				IssuerURL: "https://example.com",
			},
			expectErr: true,
			errMsg:    "at least one of allowed_project_paths or allowed_namespace_paths must be configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewValidator(tt.cfg)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, v)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestCheckAllowLists(t *testing.T) {
	tests := []struct {
		name           string
		projectPaths   []string
		namespacePaths []string
		raw            map[string]interface{}
		expectErr      bool
		errMsg         string
	}{
		{
			name:         "project_path_allowed",
			projectPaths: []string{"my-group/my-project"},
			raw:          map[string]interface{}{"project_path": "my-group/my-project"},
		},
		{
			name:           "namespace_path_allowed",
			namespacePaths: []string{"my-group"},
			raw:            map[string]interface{}{"namespace_path": "my-group"},
		},
		{
			name:         "project_path_not_allowed",
			projectPaths: []string{"my-group/my-project"},
			raw:          map[string]interface{}{"project_path": "other-group/other-project"},
			expectErr:    true,
			errMsg:       "project path",
		},
		{
			name:           "namespace_path_not_allowed",
			namespacePaths: []string{"my-group"},
			raw:            map[string]interface{}{"namespace_path": "other-group"},
			expectErr:      true,
			errMsg:         "namespace path",
		},
		{
			name:           "both_required_and_match",
			projectPaths:   []string{"my-group/my-project"},
			namespacePaths: []string{"my-group"},
			raw: map[string]interface{}{
				"project_path":   "my-group/my-project",
				"namespace_path": "my-group",
			},
		},
		{
			name:           "both_required_project_fails",
			projectPaths:   []string{"my-group/my-project"},
			namespacePaths: []string{"my-group"},
			raw: map[string]interface{}{
				"project_path":   "my-group/other-project",
				"namespace_path": "my-group",
			},
			expectErr: true,
			errMsg:    "project path",
		},
		{
			name:           "both_required_namespace_fails",
			projectPaths:   []string{"my-group/my-project"},
			namespacePaths: []string{"my-group"},
			raw: map[string]interface{}{
				"project_path":   "my-group/my-project",
				"namespace_path": "other-group",
			},
			expectErr: true,
			errMsg:    "namespace path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				allowedProjectPaths:   tt.projectPaths,
				allowedNamespacePaths: tt.namespacePaths,
			}
			err := v.checkAllowLists(tt.raw)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

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
			result := isValueAllowed(tt.value, tt.allowed)
			assert.Equal(t, tt.expected, result)
		})
	}
}

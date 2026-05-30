package github

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
			name: "valid_config_with_owners",
			cfg: Config{
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
				AllowHTTP:               true,
				IssuerURL:               "http://localhost",
			},
			expectErr: false,
		},
		{
			name: "valid_config_with_repos",
			cfg: Config{
				Audiences:           []string{"test-aud"},
				AllowedRepositories: []string{"my-org/my-repo"},
				AllowHTTP:           true,
				IssuerURL:           "http://localhost",
			},
			expectErr: false,
		},
		{
			name: "default_issuer",
			cfg: Config{
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
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
			errMsg:    "at least one of allowed_repositories or allowed_repository_owners must be configured",
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
		name      string
		owners    []string
		repos     []string
		raw       map[string]interface{}
		expectErr bool
		errMsg    string
	}{
		{
			name:   "owner_allowed",
			owners: []string{"my-org"},
			raw:    map[string]interface{}{"repository_owner": "my-org"},
		},
		{
			name:      "owner_not_allowed",
			owners:    []string{"my-org"},
			raw:       map[string]interface{}{"repository_owner": "other-org"},
			expectErr: true,
			errMsg:    "repository owner",
		},
		{
			name:  "repo_allowed",
			repos: []string{"my-org/my-repo"},
			raw:   map[string]interface{}{"repository": "my-org/my-repo"},
		},
		{
			name:      "repo_not_allowed",
			repos:     []string{"my-org/my-repo"},
			raw:       map[string]interface{}{"repository": "my-org/other-repo"},
			expectErr: true,
			errMsg:    "repository",
		},
		{
			name:   "both_required_and_match",
			owners: []string{"my-org"},
			repos:  []string{"my-org/my-repo"},
			raw: map[string]interface{}{
				"repository_owner": "my-org",
				"repository":       "my-org/my-repo",
			},
		},
		{
			name:   "both_required_owner_fails",
			owners: []string{"my-org"},
			repos:  []string{"my-org/my-repo"},
			raw: map[string]interface{}{
				"repository_owner": "other-org",
				"repository":       "my-org/my-repo",
			},
			expectErr: true,
			errMsg:    "repository owner",
		},
		{
			name:   "both_required_repo_fails",
			owners: []string{"my-org"},
			repos:  []string{"my-org/my-repo"},
			raw: map[string]interface{}{
				"repository_owner": "my-org",
				"repository":       "my-org/other-repo",
			},
			expectErr: true,
			errMsg:    "repository",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				allowedRepositoryOwners: tt.owners,
				allowedRepositories:     tt.repos,
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
			value:    "my-org/my-repo",
			allowed:  []string{"my-org/my-repo"},
			expected: true,
		},
		{
			name:     "no_match",
			value:    "my-org/my-repo",
			allowed:  []string{"other-org/other-repo"},
			expected: false,
		},
		{
			name:     "wildcard_suffix",
			value:    "my-org/my-repo",
			allowed:  []string{"my-org/*"},
			expected: true,
		},
		{
			name:     "wildcard_no_match",
			value:    "other-org/my-repo",
			allowed:  []string{"my-org/*"},
			expected: false,
		},
		{
			name:     "multiple_allowed",
			value:    "org-b/repo",
			allowed:  []string{"org-a/*", "org-b/*"},
			expected: true,
		},
		{
			name:     "empty_value",
			value:    "",
			allowed:  []string{"my-org/*"},
			expected: false,
		},
		{
			name:     "empty_allowed_list",
			value:    "my-org/my-repo",
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

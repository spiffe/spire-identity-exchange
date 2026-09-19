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
		{
			// A Forgejo instance served over http: the issuer identifies the
			// token, the discovery URL is what actually gets fetched.
			name: "http_issuer_with_https_discovery",
			cfg: Config{
				IssuerURL:               "http://forge.example.com/api/actions",
				DiscoveryURL:            "https://forge.example.com/api/actions",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: false,
		},
		{
			name: "http_discovery_rejected",
			cfg: Config{
				IssuerURL:               "https://example.com",
				DiscoveryURL:            "http://example.com",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: true,
			errMsg:    "invalid discovery URL: scheme must be https",
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

func TestConfig_ValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config",
			cfg: Config{
				IssuerURL:               "https://token.actions.githubusercontent.com",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
		},
		{
			// With a discoveryURL the issuer is only compared against the `iss`
			// claim, so its scheme is not constrained.
			name: "http_issuer_with_https_discovery_accepted",
			cfg: Config{
				IssuerURL:               "http://forge.example.com/api/actions",
				DiscoveryURL:            "https://forge.example.com/api/actions",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
		},
		{
			// Without one, the issuer is what gets fetched and inherits the
			// requirement -- reported against the field that was actually set.
			name: "http_issuer_without_discovery_rejected",
			cfg: Config{
				IssuerURL:               "http://forge.example.com/api/actions",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: true,
			errMsg:    "scheme must be https",
		},
		{
			name: "malformed_issuer",
			cfg: Config{
				IssuerURL:               "https://example.com?q=1",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: true,
			errMsg:    "query parameters are not allowed",
		},
		{
			// The discovery URL is dereferenced, so it must be https.
			name: "http_discovery_rejected",
			cfg: Config{
				IssuerURL:               "https://example.com",
				DiscoveryURL:            "http://example.com",
				Audiences:               []string{"test-aud"},
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: true,
			errMsg:    "invalid discovery URL: scheme must be https",
		},
		{
			name: "no_audiences",
			cfg: Config{
				IssuerURL:               "https://example.com",
				AllowedRepositoryOwners: []string{"my-org"},
			},
			expectErr: true,
			errMsg:    "at least one audience must be specified",
		},
		{
			name: "no_allowlists",
			cfg: Config{
				IssuerURL: "https://example.com",
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "at least one of allowedRepositories or allowedRepositoryOwners must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := cfg.ValidateConfig()
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
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


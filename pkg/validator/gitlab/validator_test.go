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
				IssuerURL:           "https://gitlab.com",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
		},
		{
			// With a discoveryURL the issuer is only compared against the `iss`
			// claim, so its scheme is not constrained.
			name: "http_issuer_with_https_discovery_accepted",
			cfg: Config{
				IssuerURL:           "http://gitlab.example.com",
				DiscoveryURL:        "https://gitlab.example.com",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
		},
		{
			// Without one, the issuer is what gets fetched and inherits the
			// requirement.
			name: "http_issuer_without_discovery_rejected",
			cfg: Config{
				IssuerURL:           "http://gitlab.example.com",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
			expectErr: true,
			errMsg:    "invalid issuer URL: scheme must be https",
		},
		{
			name: "http_discovery_rejected",
			cfg: Config{
				IssuerURL:           "https://gitlab.example.com",
				DiscoveryURL:        "http://gitlab.example.com",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
			expectErr: true,
			errMsg:    "invalid discovery URL: scheme must be https",
		},
		{
			name: "malformed_issuer",
			cfg: Config{
				IssuerURL:           "https://gitlab.example.com?q=1",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
			expectErr: true,
			errMsg:    "query parameters are not allowed",
		},
		{
			name: "no_audiences",
			cfg: Config{
				IssuerURL:           "https://gitlab.com",
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
			expectErr: true,
			errMsg:    "at least one audience must be specified",
		},
		{
			name: "no_allowlists",
			cfg: Config{
				IssuerURL: "https://gitlab.com",
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "at least one of allowedProjectPaths or allowedNamespacePaths must be specified",
		},
		{
			name: "discovery_spiffe_id_with_plugin_socket",
			cfg: Config{
				IssuerURL:               "https://gitlab.com",
				DiscoverySPIFFEID:       "spiffe://example.org/oidc-discovery-provider",
				AgentWorkloadSocketPath: "/plugin.sock",
				Audiences:               []string{"test-aud"},
				AllowedProjectPaths:     []string{"my-org/my-project"},
			},
		},
		{
			name: "discovery_spiffe_id_without_any_socket",
			cfg: Config{
				IssuerURL:           "https://gitlab.com",
				DiscoverySPIFFEID:   "spiffe://example.org/oidc-discovery-provider",
				Audiences:           []string{"test-aud"},
				AllowedProjectPaths: []string{"my-org/my-project"},
			},
			expectErr: true,
			errMsg:    "workload API socket path must be available",
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


func TestConfig_SetDefaultWorkloadAPISocketPath(t *testing.T) {
	base := func() Config {
		return Config{
			IssuerURL:           "https://gitlab.com",
			DiscoverySPIFFEID:   "spiffe://example.org/oidc-discovery-provider",
			Audiences:           []string{"test-aud"},
			AllowedProjectPaths: []string{"my-org/my-project"},
		}
	}

	t.Run("server_level_satisfies_the_requirement", func(t *testing.T) {
		cfg := base()
		require.Error(t, cfg.ValidateConfig(), "precondition: no socket anywhere")

		cfg = base()
		cfg.SetDefaultWorkloadAPISocketPath("/server.sock")
		assert.NoError(t, cfg.ValidateConfig())
		assert.Equal(t, "/server.sock", cfg.workloadAPISocketPath())
	})

	t.Run("plugin_level_overrides_server_level", func(t *testing.T) {
		cfg := base()
		cfg.AgentWorkloadSocketPath = "/plugin.sock"
		cfg.SetDefaultWorkloadAPISocketPath("/server.sock")
		assert.NoError(t, cfg.ValidateConfig())
		assert.Equal(t, "/plugin.sock", cfg.workloadAPISocketPath())
	})

	t.Run("empty_default_is_harmless_without_a_spiffe_id", func(t *testing.T) {
		cfg := base()
		cfg.DiscoverySPIFFEID = ""
		cfg.SetDefaultWorkloadAPISocketPath("")
		assert.NoError(t, cfg.ValidateConfig())
	})
}

package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

func TestBuildSelectors(t *testing.T) {
	tests := []struct {
		name           string
		claims         *Claims
		expectContains []string
		expectAbsent   []string
		expectCount    int
	}{
		{
			name: "full_claims_with_branch",
			claims: &Claims{
				NamespaceID:          "72",
				NamespacePath:        "my-group",
				ProjectID:            "20",
				ProjectPath:          "my-group/my-project",
				ProjectVisibility:    "public",
				UserID:               "1",
				UserLogin:            "sample-user",
				UserEmail:            "sample-user@example.com",
				UserAccessLevel:      "developer",
				JobProjectID:         "20",
				JobProjectPath:       "my-group/my-project",
				JobNamespaceID:       "72",
				JobNamespacePath:     "my-group",
				PipelineID:           "574",
				PipelineSource:       "push",
				JobID:                "302",
				JobSource:            "push",
				Ref:                  "feature-branch-1",
				RefType:              "branch",
				RefPath:              "refs/heads/feature-branch-1",
				RefProtected:         "false",
				Environment:          "test-environment2",
				EnvironmentProtected: "false",
				DeploymentTier:       "testing",
				EnvironmentAction:    "start",
				RunnerID:             "1",
				RunnerEnvironment:    "self-hosted",
				SHA:                  "714a629c0b401fdce83e847fc9589983fc6f46bc",
				CIConfigRefURI:       "gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
				CIConfigSHA:          "714a629c0b401fdce83e847fc9589983fc6f46bc",
				Subject:              "project_path:my-group/my-project:ref_type:branch:ref:feature-branch-1",
			},
			expectContains: []string{
				"project_path:my-group/my-project",
				"namespace_path:my-group",
				"branch:feature-branch-1",
				"ref_path:refs/heads/feature-branch-1",
				"ref_type:branch",
				"sha:714a629c0b401fdce83e847fc9589983fc6f46bc",
				"user_login:sample-user",
				"environment:test-environment2",
				"ci_config_ref_uri:host:gitlab.example.com",
				"ci_config_ref_uri:project_path:my-group/my-project",
				"ci_config_ref_uri:config_path:.gitlab-ci.yml",
				"ci_config_ref_uri:ref:refs/heads/main",
			},
			expectCount: 36,
		},
		{
			name: "tag_ref_no_branch",
			claims: &Claims{
				RefType: "tag",
				Ref:     "v1.0.0",
				RefPath: "refs/tags/v1.0.0",
			},
			expectContains: []string{
				"ref:v1.0.0",
				"ref_path:refs/tags/v1.0.0",
				"ref_type:tag",
			},
			expectAbsent: []string{"branch:"},
			expectCount:  3,
		},
		{
			name: "empty_fields_skipped",
			claims: &Claims{
				ProjectPath: "my-group/my-project",
				UserLogin:   "sample-user",
			},
			expectContains: []string{
				"project_path:my-group/my-project",
				"user_login:sample-user",
			},
			expectCount: 2,
		},
		{
			name:        "all_empty",
			claims:      &Claims{},
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selectors := buildSelectors(tt.claims)

			assert.Len(t, selectors, tt.expectCount)

			for _, s := range selectors {
				assert.Equal(t, SelectorType, s.Type)
			}

			values := make([]string, len(selectors))
			for i, s := range selectors {
				values[i] = s.Value
			}

			for _, expected := range tt.expectContains {
				assert.Contains(t, values, expected)
			}

			for _, absent := range tt.expectAbsent {
				for _, v := range values {
					assert.NotContains(t, v, absent)
				}
			}
		})
	}
}

func TestParseCIConfigRefURI(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectOK          bool
		expectHost        string
		expectProjectPath string
		expectConfigPath  string
		expectRef         string
	}{
		{
			name:              "standard_uri",
			input:             "gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
			expectOK:          true,
			expectHost:        "gitlab.example.com",
			expectProjectPath: "my-group/my-project",
			expectConfigPath:  ".gitlab-ci.yml",
			expectRef:         "refs/heads/main",
		},
		{
			name:              "gitlab_com",
			input:             "gitlab.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
			expectOK:          true,
			expectHost:        "gitlab.com",
			expectProjectPath: "my-group/my-project",
			expectConfigPath:  ".gitlab-ci.yml",
			expectRef:         "refs/heads/main",
		},
		{
			name:              "nested_group",
			input:             "gitlab.com/my-group/sub-group/my-project//.gitlab-ci.yml@refs/tags/v1.0.0",
			expectOK:          true,
			expectHost:        "gitlab.com",
			expectProjectPath: "my-group/sub-group/my-project",
			expectConfigPath:  ".gitlab-ci.yml",
			expectRef:         "refs/tags/v1.0.0",
		},
		{
			name:              "custom_config_path",
			input:             "gitlab.com/my-group/my-project//.gitlab/ci-template.yml@abc123",
			expectOK:          true,
			expectHost:        "gitlab.com",
			expectProjectPath: "my-group/my-project",
			expectConfigPath:  ".gitlab/ci-template.yml",
			expectRef:         "abc123",
		},
		{
			name:     "empty_string",
			input:    "",
			expectOK: false,
		},
		{
			name:     "no_at_sign",
			input:    "gitlab.com/my-group/my-project//.gitlab-ci.yml",
			expectOK: false,
		},
		{
			name:     "no_double_slash",
			input:    "gitlab.com/my-group/my-project@refs/heads/main",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, projectPath, configPath, ref, ok := parseCIConfigRefURI(tt.input)
			assert.Equal(t, tt.expectOK, ok)
			if tt.expectOK {
				assert.Equal(t, tt.expectHost, host)
				assert.Equal(t, tt.expectProjectPath, projectPath)
				assert.Equal(t, tt.expectConfigPath, configPath)
				assert.Equal(t, tt.expectRef, ref)
			}
		})
	}
}

func TestBuildSelectors_CIConfigRefURIDecomposition(t *testing.T) {
	claims := &Claims{
		CIConfigRefURI: "gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
	}

	selectors := buildSelectors(claims)

	values := make([]string, len(selectors))
	for i, s := range selectors {
		values[i] = s.Value
	}

	assert.Contains(t, values, "ci_config_ref_uri:gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main")

	assert.Contains(t, values, "ci_config_ref_uri:host:gitlab.example.com")
	assert.Contains(t, values, "ci_config_ref_uri:project_path:my-group/my-project")
	assert.Contains(t, values, "ci_config_ref_uri:config_path:.gitlab-ci.yml")
	assert.Contains(t, values, "ci_config_ref_uri:ref:refs/heads/main")

	assert.Len(t, selectors, 5)
}

func TestGenerateSelectors_ViaValidator(t *testing.T) {
	claims := &validator.JWTClaims{
		Raw: map[string]interface{}{
			"project_path":   "my-group/my-project",
			"namespace_path": "my-group",
			"ref_path":       "refs/heads/main",
			"ref_type":       "branch",
			"user_login":     "sample-user",
		},
	}

	v := &Validator{}
	selectors := v.GenerateSelectors(claims)

	require.NotEmpty(t, selectors)

	values := make([]string, len(selectors))
	for i, s := range selectors {
		values[i] = s.Value
	}

	assert.Contains(t, values, "project_path:my-group/my-project")
	assert.Contains(t, values, "namespace_path:my-group")
	assert.Contains(t, values, "branch:main")
}

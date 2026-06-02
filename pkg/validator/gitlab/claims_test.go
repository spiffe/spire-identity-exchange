package gitlab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaimsFromRaw(t *testing.T) {
	tests := []struct {
		name   string
		raw    map[string]interface{}
		verify func(t *testing.T, c *Claims)
	}{
		{
			name: "all_fields",
			raw: map[string]interface{}{
				"namespace_id":          "72",
				"namespace_path":        "my-group",
				"project_id":            "20",
				"project_path":          "my-group/my-project",
				"project_visibility":    "public",
				"user_id":               "1",
				"user_login":            "sample-user",
				"user_email":            "sample-user@example.com",
				"user_access_level":     "developer",
				"job_project_id":        "20",
				"job_project_path":      "my-group/my-project",
				"job_namespace_id":      "72",
				"job_namespace_path":    "my-group",
				"pipeline_id":           "574",
				"pipeline_source":       "push",
				"job_id":                "302",
				"job_source":            "push",
				"ref":                   "feature-branch-1",
				"ref_type":              "branch",
				"ref_path":              "refs/heads/feature-branch-1",
				"ref_protected":         "false",
				"environment":           "test-environment2",
				"environment_protected": "false",
				"deployment_tier":       "testing",
				"environment_action":    "start",
				"runner_id":             "1",
				"runner_environment":    "self-hosted",
				"sha":                   "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"ci_config_ref_uri":     "gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main",
				"ci_config_sha":         "714a629c0b401fdce83e847fc9589983fc6f46bc",
				"sub":                   "project_path:my-group/my-project:ref_type:branch:ref:feature-branch-1",
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "72", c.NamespaceID)
				assert.Equal(t, "my-group", c.NamespacePath)
				assert.Equal(t, "20", c.ProjectID)
				assert.Equal(t, "my-group/my-project", c.ProjectPath)
				assert.Equal(t, "public", c.ProjectVisibility)
				assert.Equal(t, "1", c.UserID)
				assert.Equal(t, "sample-user", c.UserLogin)
				assert.Equal(t, "sample-user@example.com", c.UserEmail)
				assert.Equal(t, "developer", c.UserAccessLevel)
				assert.Equal(t, "20", c.JobProjectID)
				assert.Equal(t, "my-group/my-project", c.JobProjectPath)
				assert.Equal(t, "72", c.JobNamespaceID)
				assert.Equal(t, "my-group", c.JobNamespacePath)
				assert.Equal(t, "574", c.PipelineID)
				assert.Equal(t, "push", c.PipelineSource)
				assert.Equal(t, "302", c.JobID)
				assert.Equal(t, "push", c.JobSource)
				assert.Equal(t, "feature-branch-1", c.Ref)
				assert.Equal(t, "branch", c.RefType)
				assert.Equal(t, "refs/heads/feature-branch-1", c.RefPath)
				assert.Equal(t, "false", c.RefProtected)
				assert.Equal(t, "test-environment2", c.Environment)
				assert.Equal(t, "false", c.EnvironmentProtected)
				assert.Equal(t, "testing", c.DeploymentTier)
				assert.Equal(t, "start", c.EnvironmentAction)
				assert.Equal(t, "1", c.RunnerID)
				assert.Equal(t, "self-hosted", c.RunnerEnvironment)
				assert.Equal(t, "714a629c0b401fdce83e847fc9589983fc6f46bc", c.SHA)
				assert.Equal(t, "gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main", c.CIConfigRefURI)
				assert.Equal(t, "714a629c0b401fdce83e847fc9589983fc6f46bc", c.CIConfigSHA)
				assert.Equal(t, "project_path:my-group/my-project:ref_type:branch:ref:feature-branch-1", c.Subject)
			},
		},
		{
			name: "nil_map",
			raw:  nil,
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.ProjectPath)
				assert.Equal(t, "", c.NamespacePath)
				assert.Equal(t, "", c.UserLogin)
			},
		},
		{
			name: "empty_map",
			raw:  map[string]interface{}{},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.ProjectPath)
				assert.Equal(t, "", c.NamespacePath)
			},
		},
		{
			name: "missing_keys",
			raw: map[string]interface{}{
				"project_path": "my-group/my-project",
				"user_login":   "sample-user",
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "my-group/my-project", c.ProjectPath)
				assert.Equal(t, "sample-user", c.UserLogin)
				assert.Equal(t, "", c.NamespacePath)
				assert.Equal(t, "", c.PipelineID)
			},
		},
		{
			name: "non_string_values",
			raw: map[string]interface{}{
				"project_id": 12345,
				"user_id":    true,
				"runner_id":  1,
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.ProjectID)
				assert.Equal(t, "", c.UserID)
				assert.Equal(t, "", c.RunnerID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := claimsFromRaw(tt.raw)
			assert.NotNil(t, c)
			tt.verify(t, c)
		})
	}
}

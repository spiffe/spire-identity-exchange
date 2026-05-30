package github

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
				"repository":            "my-org/my-repo",
				"repository_owner":      "my-org",
				"repository_id":         "12345",
				"repository_owner_id":   "67890",
				"repository_visibility": "public",
				"workflow":              "CI",
				"workflow_ref":          "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
				"job_workflow_ref":      "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
				"ref":                   "refs/heads/main",
				"ref_type":              "branch",
				"sha":                   "abc123",
				"head_ref":              "",
				"base_ref":              "",
				"event_name":            "push",
				"actor":                 "test-user",
				"actor_id":              "111",
				"run_id":                "9999",
				"run_number":            "42",
				"run_attempt":           "1",
				"environment":           "production",
				"environment_node_id":   "EN_123",
				"runner_environment":    "github-hosted",
				"workflow_sha":          "def456",
				"job_workflow_sha":      "ghi789",
				"ref_protected":         "true",
				"enterprise":            "my-enterprise",
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "my-org/my-repo", c.Repository)
				assert.Equal(t, "my-org", c.RepositoryOwner)
				assert.Equal(t, "12345", c.RepositoryID)
				assert.Equal(t, "67890", c.RepositoryOwnerID)
				assert.Equal(t, "public", c.RepositoryVisibility)
				assert.Equal(t, "CI", c.Workflow)
				assert.Equal(t, "refs/heads/main", c.Ref)
				assert.Equal(t, "branch", c.RefType)
				assert.Equal(t, "abc123", c.SHA)
				assert.Equal(t, "push", c.EventName)
				assert.Equal(t, "test-user", c.Actor)
				assert.Equal(t, "111", c.ActorID)
				assert.Equal(t, "9999", c.RunID)
				assert.Equal(t, "42", c.RunNumber)
				assert.Equal(t, "1", c.RunAttempt)
				assert.Equal(t, "production", c.Environment)
				assert.Equal(t, "EN_123", c.EnvironmentNodeID)
				assert.Equal(t, "github-hosted", c.RunnerEnvironment)
				assert.Equal(t, "def456", c.WorkflowSHA)
				assert.Equal(t, "ghi789", c.JobWorkflowSHA)
				assert.Equal(t, "true", c.RefProtected)
				assert.Equal(t, "my-enterprise", c.Enterprise)
			},
		},
		{
			name: "nil_map",
			raw:  nil,
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.Repository)
				assert.Equal(t, "", c.RepositoryOwner)
				assert.Equal(t, "", c.Actor)
			},
		},
		{
			name: "empty_map",
			raw:  map[string]interface{}{},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.Repository)
				assert.Equal(t, "", c.RepositoryOwner)
			},
		},
		{
			name: "missing_keys",
			raw: map[string]interface{}{
				"repository": "my-org/my-repo",
				"actor":      "test-user",
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "my-org/my-repo", c.Repository)
				assert.Equal(t, "test-user", c.Actor)
				assert.Equal(t, "", c.RepositoryOwner)
				assert.Equal(t, "", c.Workflow)
			},
		},
		{
			name: "non_string_values",
			raw: map[string]interface{}{
				"repository": 12345,
				"actor":      true,
				"run_id":     999,
			},
			verify: func(t *testing.T, c *Claims) {
				assert.Equal(t, "", c.Repository)
				assert.Equal(t, "", c.Actor)
				assert.Equal(t, "", c.RunID)
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

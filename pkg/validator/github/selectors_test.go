package github

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
				Repository:           "my-org/my-repo",
				RepositoryOwner:      "my-org",
				RepositoryID:         "12345",
				RepositoryOwnerID:    "67890",
				RepositoryVisibility: "public",
				Workflow:             "CI",
				WorkflowRef:          "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
				JobWorkflowRef:       "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
				Ref:                  "refs/heads/main",
				RefType:              "branch",
				SHA:                  "abc123",
				HeadRef:              "feature-branch",
				BaseRef:              "main",
				EventName:            "push",
				Actor:                "test-user",
				ActorID:              "111",
				RunID:                "9999",
				RunNumber:            "42",
				RunAttempt:           "1",
				Environment:          "production",
				RunnerEnvironment:    "github-hosted",
			},
			expectContains: []string{
				"repository:my-org/my-repo",
				"repository_owner:my-org",
				"branch:main",
				"ref:refs/heads/main",
				"ref_type:branch",
				"sha:abc123",
				"actor:test-user",
				"environment:production",
				"workflow_ref:repo:my-org/my-repo",
				"workflow_ref:path:.github/workflows/ci.yml",
				"workflow_ref:ref:refs/heads/main",
				"job_workflow_ref:repo:my-org/my-repo",
				"job_workflow_ref:path:.github/workflows/ci.yml",
				"job_workflow_ref:ref:refs/heads/main",
			},
			expectCount: 28, // 21 fields + 1 branch + 6 decomposed (3 each for workflow_ref and job_workflow_ref)
		},
		{
			name: "branch_extraction_nested_path",
			claims: &Claims{
				RefType: "branch",
				Ref:     "refs/heads/feature/deep/path",
			},
			expectContains: []string{
				"branch:feature/deep/path",
				"ref:refs/heads/feature/deep/path",
				"ref_type:branch",
			},
			expectCount: 3, // ref, ref_type, branch
		},
		{
			name: "tag_ref_no_branch",
			claims: &Claims{
				RefType: "tag",
				Ref:     "refs/tags/v1.0.0",
			},
			expectContains: []string{
				"ref:refs/tags/v1.0.0",
				"ref_type:tag",
			},
			expectAbsent: []string{"branch:"},
			expectCount:  2,
		},
		{
			name: "empty_fields_skipped",
			claims: &Claims{
				Repository: "my-org/my-repo",
				Actor:      "test-user",
			},
			expectContains: []string{
				"repository:my-org/my-repo",
				"actor:test-user",
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

			// Verify all selectors have correct type.
			for _, s := range selectors {
				assert.Equal(t, SelectorType, s.Type)
			}

			// Check expected values are present.
			values := make([]string, len(selectors))
			for i, s := range selectors {
				values[i] = s.Value
			}

			for _, expected := range tt.expectContains {
				assert.Contains(t, values, expected)
			}

			// Check absent values.
			for _, absent := range tt.expectAbsent {
				for _, v := range values {
					assert.NotContains(t, v, absent)
				}
			}
		})
	}
}

func TestParseWorkflowRef(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectOK     bool
		expectRepo   string
		expectPath   string
		expectRef    string
	}{
		{
			name:       "standard_workflow_ref",
			input:      "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
			expectOK:   true,
			expectRepo: "my-org/my-repo",
			expectPath: ".github/workflows/ci.yml",
			expectRef:  "refs/heads/main",
		},
		{
			name:       "tag_ref",
			input:      "my-org/my-repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			expectOK:   true,
			expectRepo: "my-org/my-repo",
			expectPath: ".github/workflows/release.yml",
			expectRef:  "refs/tags/v1.0.0",
		},
		{
			name:       "nested_workflow_path",
			input:      "org/repo/.github/workflows/sub/deploy.yml@refs/heads/main",
			expectOK:   true,
			expectRepo: "org/repo",
			expectPath: ".github/workflows/sub/deploy.yml",
			expectRef:  "refs/heads/main",
		},
		{
			name:       "sha_ref",
			input:      "my-org/my-repo/.github/workflows/ci.yml@abc123def456",
			expectOK:   true,
			expectRepo: "my-org/my-repo",
			expectPath: ".github/workflows/ci.yml",
			expectRef:  "abc123def456",
		},
		{
			name:     "empty_string",
			input:    "",
			expectOK: false,
		},
		{
			name:     "no_at_sign",
			input:    "my-org/my-repo/.github/workflows/ci.yml",
			expectOK: false,
		},
		{
			name:     "no_github_dir",
			input:    "my-org/my-repo/workflows/ci.yml@refs/heads/main",
			expectOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, path, ref, ok := parseWorkflowRef(tt.input)
			assert.Equal(t, tt.expectOK, ok)
			if tt.expectOK {
				assert.Equal(t, tt.expectRepo, repo)
				assert.Equal(t, tt.expectPath, path)
				assert.Equal(t, tt.expectRef, ref)
			}
		})
	}
}

func TestBuildSelectors_WorkflowRefDecomposition(t *testing.T) {
	claims := &Claims{
		WorkflowRef:    "my-org/my-repo/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowRef: "other-org/other-repo/.github/workflows/reusable.yml@refs/tags/v1.0.0",
	}

	selectors := buildSelectors(claims)

	values := make([]string, len(selectors))
	for i, s := range selectors {
		values[i] = s.Value
	}

	// Original full values.
	assert.Contains(t, values, "workflow_ref:my-org/my-repo/.github/workflows/ci.yml@refs/heads/main")
	assert.Contains(t, values, "job_workflow_ref:other-org/other-repo/.github/workflows/reusable.yml@refs/tags/v1.0.0")

	// Decomposed workflow_ref.
	assert.Contains(t, values, "workflow_ref:repo:my-org/my-repo")
	assert.Contains(t, values, "workflow_ref:path:.github/workflows/ci.yml")
	assert.Contains(t, values, "workflow_ref:ref:refs/heads/main")

	// Decomposed job_workflow_ref.
	assert.Contains(t, values, "job_workflow_ref:repo:other-org/other-repo")
	assert.Contains(t, values, "job_workflow_ref:path:.github/workflows/reusable.yml")
	assert.Contains(t, values, "job_workflow_ref:ref:refs/tags/v1.0.0")

	// 2 original + 6 decomposed = 8
	assert.Len(t, selectors, 8)
}

func TestGenerateSelectors_ViaValidator(t *testing.T) {
	claims := &validator.JWTClaims{
		Raw: map[string]interface{}{
			"repository":       "my-org/my-repo",
			"repository_owner": "my-org",
			"ref":              "refs/heads/main",
			"ref_type":         "branch",
			"actor":            "test-user",
		},
	}

	// Create a Validator with minimal config to test GenerateSelectors.
	// We only need the struct, not a fully initialized validator.
	v := &Validator{}
	selectors := v.GenerateSelectors(claims)

	require.NotEmpty(t, selectors)

	values := make([]string, len(selectors))
	for i, s := range selectors {
		values[i] = s.Value
	}

	assert.Contains(t, values, "repository:my-org/my-repo")
	assert.Contains(t, values, "repository_owner:my-org")
	assert.Contains(t, values, "branch:main")
}

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
			},
			expectCount: 22, // 21 fields + 1 branch
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

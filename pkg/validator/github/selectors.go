package github

import (
	"fmt"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const SelectorType = "github_actions"

// GenerateSelectors produces SPIRE selectors from validated GitHub OIDC claims.
// Implements validator.SelectorGenerator.
func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
	gh := claimsFromRaw(claims.GetRaw())
	return buildSelectors(gh)
}

func buildSelectors(c *Claims) []*types.Selector {
	var selectors []*types.Selector

	add := func(key, value string) {
		if value != "" {
			selectors = append(selectors, &types.Selector{
				Type:  SelectorType,
				Value: fmt.Sprintf("%s:%s", key, value),
			})
		}
	}

	add("repository", c.Repository)
	add("repository_owner", c.RepositoryOwner)
	add("repository_id", c.RepositoryID)
	add("repository_owner_id", c.RepositoryOwnerID)
	add("repository_visibility", c.RepositoryVisibility)

	add("workflow", c.Workflow)
	add("workflow_ref", c.WorkflowRef)
	addWorkflowRefParts("workflow_ref", c.WorkflowRef, add)
	add("job_workflow_ref", c.JobWorkflowRef)
	addWorkflowRefParts("job_workflow_ref", c.JobWorkflowRef, add)

	add("ref", c.Ref)
	add("ref_type", c.RefType)
	add("sha", c.SHA)
	add("head_ref", c.HeadRef)
	add("base_ref", c.BaseRef)

	if c.RefType == "branch" && strings.HasPrefix(c.Ref, "refs/heads/") {
		add("branch", strings.TrimPrefix(c.Ref, "refs/heads/"))
	}

	add("event_name", c.EventName)
	add("actor", c.Actor)
	add("actor_id", c.ActorID)

	add("run_id", c.RunID)
	add("run_number", c.RunNumber)
	add("run_attempt", c.RunAttempt)

	add("environment", c.Environment)
	add("runner_environment", c.RunnerEnvironment)

	return selectors
}

// parseWorkflowRef splits a workflow ref string like
// "owner/repo/.github/workflows/ci.yml@refs/heads/main" into its components.
// Returns (repo, path, ref, ok).
func parseWorkflowRef(workflowRef string) (repo, path, ref string, ok bool) {
	if workflowRef == "" {
		return "", "", "", false
	}

	// Split at "@" to separate the base from the git ref.
	atIdx := strings.LastIndex(workflowRef, "@")
	if atIdx < 0 {
		return "", "", "", false
	}
	base := workflowRef[:atIdx]
	ref = workflowRef[atIdx+1:]

	// Split at "/.github/" to separate repo from workflow path.
	const sep = "/.github/"
	sepIdx := strings.Index(base, sep)
	if sepIdx < 0 {
		return "", "", "", false
	}
	repo = base[:sepIdx]
	path = base[sepIdx+1:] // includes ".github/..."

	if repo == "" || path == "" || ref == "" {
		return "", "", "", false
	}

	return repo, path, ref, true
}

// addWorkflowRefParts adds decomposed selectors for a workflow ref field.
func addWorkflowRefParts(prefix string, value string, add func(string, string)) {
	repo, path, ref, ok := parseWorkflowRef(value)
	if !ok {
		return
	}
	add(prefix+":repo", repo)
	add(prefix+":path", path)
	add(prefix+":ref", ref)
}

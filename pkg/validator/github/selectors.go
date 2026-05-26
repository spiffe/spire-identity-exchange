package github

import (
	"fmt"
	"strings"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const SelectorType = "github_actions"

// GenerateSelectors produces SPIRE selectors from validated GitHub OIDC claims.
// Implements validator.SelectorGenerator.
func (v *Validator) GenerateSelectors(claims validator.Claims) []validator.Selector {
	gh := claimsFromRaw(claims.GetRaw())
	return buildSelectors(gh)
}

func buildSelectors(c *Claims) []validator.Selector {
	var selectors []validator.Selector

	add := func(key, value string) {
		if value != "" {
			selectors = append(selectors, validator.Selector{
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
	add("job_workflow_ref", c.JobWorkflowRef)

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

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

// claimsFromRaw reconstructs GitHub Claims from the raw claims map.
func claimsFromRaw(raw map[string]interface{}) *Claims {
	c := &Claims{}
	getString := func(key string) string {
		if v, ok := raw[key].(string); ok {
			return v
		}
		return ""
	}
	c.Repository = getString("repository")
	c.RepositoryOwner = getString("repository_owner")
	c.RepositoryID = getString("repository_id")
	c.RepositoryOwnerID = getString("repository_owner_id")
	c.RepositoryVisibility = getString("repository_visibility")
	c.Workflow = getString("workflow")
	c.WorkflowRef = getString("workflow_ref")
	c.JobWorkflowRef = getString("job_workflow_ref")
	c.Ref = getString("ref")
	c.RefType = getString("ref_type")
	c.SHA = getString("sha")
	c.HeadRef = getString("head_ref")
	c.BaseRef = getString("base_ref")
	c.EventName = getString("event_name")
	c.Actor = getString("actor")
	c.ActorID = getString("actor_id")
	c.RunID = getString("run_id")
	c.RunNumber = getString("run_number")
	c.RunAttempt = getString("run_attempt")
	c.Environment = getString("environment")
	c.EnvironmentNodeID = getString("environment_node_id")
	c.RunnerEnvironment = getString("runner_environment")
	c.WorkflowSHA = getString("workflow_sha")
	c.JobWorkflowSHA = getString("job_workflow_sha")
	c.RefProtected = getString("ref_protected")
	c.Enterprise = getString("enterprise")
	return c
}

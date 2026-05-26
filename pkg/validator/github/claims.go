package github

// Claims holds GitHub Actions OIDC specific claim fields.
// Used internally for typed access when generating selectors.
type Claims struct {
	Repository           string
	RepositoryID         string
	RepositoryOwner      string
	RepositoryOwnerID    string
	RepositoryVisibility string
	Workflow             string
	WorkflowRef          string
	WorkflowSHA          string
	JobWorkflowRef       string
	JobWorkflowSHA       string
	Ref                  string
	RefType              string
	RefProtected         string
	SHA                  string
	HeadRef              string
	BaseRef              string
	EventName            string
	Actor                string
	ActorID              string
	RunID                string
	RunNumber            string
	RunAttempt           string
	Environment          string
	EnvironmentNodeID    string
	RunnerEnvironment    string
	Enterprise           string
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

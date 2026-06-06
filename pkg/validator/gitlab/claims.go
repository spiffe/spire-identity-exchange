package gitlab

type Claims struct {
	NamespaceID          string
	NamespacePath        string
	ProjectID            string
	ProjectPath          string
	ProjectVisibility    string
	UserID               string
	UserLogin            string
	UserEmail            string
	UserAccessLevel      string
	JobProjectID         string
	JobProjectPath       string
	JobNamespaceID       string
	JobNamespacePath     string
	PipelineID           string
	PipelineSource       string
	JobID                string
	JobSource            string
	Ref                  string
	RefType              string
	RefPath              string
	RefProtected         string
	Environment          string
	EnvironmentProtected string
	DeploymentTier       string
	EnvironmentAction    string
	RunnerID             string
	RunnerEnvironment    string
	SHA                  string
	CIConfigRefURI       string
	CIConfigSHA          string
	Subject              string
}

func claimsFromRaw(raw map[string]interface{}) *Claims {
	c := &Claims{}
	getString := func(key string) string {
		if v, ok := raw[key].(string); ok {
			return v
		}
		return ""
	}
	c.NamespaceID = getString("namespace_id")
	c.NamespacePath = getString("namespace_path")
	c.ProjectID = getString("project_id")
	c.ProjectPath = getString("project_path")
	c.ProjectVisibility = getString("project_visibility")
	c.UserID = getString("user_id")
	c.UserLogin = getString("user_login")
	c.UserEmail = getString("user_email")
	c.UserAccessLevel = getString("user_access_level")
	c.JobProjectID = getString("job_project_id")
	c.JobProjectPath = getString("job_project_path")
	c.JobNamespaceID = getString("job_namespace_id")
	c.JobNamespacePath = getString("job_namespace_path")
	c.PipelineID = getString("pipeline_id")
	c.PipelineSource = getString("pipeline_source")
	c.JobID = getString("job_id")
	c.JobSource = getString("job_source")
	c.Ref = getString("ref")
	c.RefType = getString("ref_type")
	c.RefPath = getString("ref_path")
	c.RefProtected = getString("ref_protected")
	c.Environment = getString("environment")
	c.EnvironmentProtected = getString("environment_protected")
	c.DeploymentTier = getString("deployment_tier")
	c.EnvironmentAction = getString("environment_action")
	c.RunnerID = getString("runner_id")
	c.RunnerEnvironment = getString("runner_environment")
	c.SHA = getString("sha")
	c.CIConfigRefURI = getString("ci_config_ref_uri")
	c.CIConfigSHA = getString("ci_config_sha")
	c.Subject = getString("sub")
	return c
}

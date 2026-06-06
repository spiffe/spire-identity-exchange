package gitlab

import (
	"fmt"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const SelectorType = "gitlab_ci"

func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
	gl := claimsFromRaw(claims.GetRaw())
	return buildSelectors(gl)
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

	add("namespace_id", c.NamespaceID)
	add("namespace_path", c.NamespacePath)
	add("project_id", c.ProjectID)
	add("project_path", c.ProjectPath)
	add("project_visibility", c.ProjectVisibility)

	add("user_id", c.UserID)
	add("user_login", c.UserLogin)
	add("user_email", c.UserEmail)
	add("user_access_level", c.UserAccessLevel)

	add("job_project_id", c.JobProjectID)
	add("job_project_path", c.JobProjectPath)
	add("job_namespace_id", c.JobNamespaceID)
	add("job_namespace_path", c.JobNamespacePath)

	add("pipeline_id", c.PipelineID)
	add("pipeline_source", c.PipelineSource)

	add("job_id", c.JobID)
	add("job_source", c.JobSource)

	add("ref", c.Ref)
	add("ref_type", c.RefType)
	add("ref_path", c.RefPath)
	add("ref_protected", c.RefProtected)
	add("sha", c.SHA)

	if c.RefType == "branch" && strings.HasPrefix(c.RefPath, "refs/heads/") {
		branch := strings.TrimPrefix(c.RefPath, "refs/heads/")
		if branch != "" {
			add("branch", branch)
		}
	}

	add("environment", c.Environment)
	add("environment_protected", c.EnvironmentProtected)
	add("deployment_tier", c.DeploymentTier)
	add("environment_action", c.EnvironmentAction)

	add("runner_id", c.RunnerID)
	add("runner_environment", c.RunnerEnvironment)

	add("ci_config_ref_uri", c.CIConfigRefURI)
	addCIConfigRefURIParts("ci_config_ref_uri", c.CIConfigRefURI, add)

	add("ci_config_sha", c.CIConfigSHA)

	add("sub", c.Subject)

	return selectors
}

func parseCIConfigRefURI(uri string) (host, projectPath, configPath, ref string, ok bool) {
	if uri == "" {
		return "", "", "", "", false
	}

	atIdx := strings.LastIndex(uri, "@")
	if atIdx < 0 {
		return "", "", "", "", false
	}
	base := uri[:atIdx]
	ref = uri[atIdx+1:]

	sepIdx := strings.Index(base, "//")
	if sepIdx < 0 {
		return "", "", "", "", false
	}
	hostProject := base[:sepIdx]
	configPath = base[sepIdx+2:]

	slashIdx := strings.Index(hostProject, "/")
	if slashIdx < 0 {
		return "", "", "", "", false
	}
	host = hostProject[:slashIdx]
	projectPath = hostProject[slashIdx+1:]

	if host == "" || projectPath == "" || configPath == "" || ref == "" {
		return "", "", "", "", false
	}

	return host, projectPath, configPath, ref, true
}

func addCIConfigRefURIParts(prefix string, value string, add func(string, string)) {
	host, projectPath, configPath, ref, ok := parseCIConfigRefURI(value)
	if !ok {
		return
	}
	add(prefix+":host", host)
	add(prefix+":project_path", projectPath)
	add(prefix+":config_path", configPath)
	add(prefix+":ref", ref)
}

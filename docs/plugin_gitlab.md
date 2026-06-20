# Auth plugin: GitLab CI/CD OIDC "gitlab"

Validates GitLab CI/CD OIDC tokens (JWTs issued by `https://gitlab.com` or a self-hosted GitLab instance) and generates SPIRE selectors that identify the caller by project, namespace, pipeline, environment, and other GitLab-specific attributes.

Uses the generic [JWT validator](pkg/validator/jwt/) for signature verification, key discovery, and standard claim validation. Adds GitLab-specific allowlist checks and selector generation on top.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuerURL` | string | no | OIDC issuer. Default: `https://gitlab.com`. Must be HTTPS unless `AllowHTTP` is set for testing. |
| `audiences` | string array | **yes** | Expected JWT audience values. At least one entry required. |
| `allowedNamespacePaths` | string array | see note | GitLab group/user paths allowed (e.g. `my-org`). Supports trailing wildcard (`*`). At least one of `allowedNamespacePaths` or `allowedProjectPaths` must be set. |
| `allowedProjectPaths` | string array | see note | GitLab project paths allowed (e.g. `my-org/my-project`). Supports trailing wildcard (`*`). At least one required if `allowedNamespacePaths` is empty. |

When both `allowedNamespacePaths` and `allowedProjectPaths` are set, the token must match **both** lists (AND logic).

## Selector reference

Selector type: `gitlab_ci`

| Selector key | Value format | Condition |
|---|---|---|
| `namespace_id` | numeric | always |
| `namespace_path` | group/user path | always |
| `project_id` | numeric | always |
| `project_path` | `group/project` | always |
| `project_visibility` | visibility string | always |
| `user_id` | numeric | always |
| `user_login` | username | always |
| `user_email` | email | always |
| `user_access_level` | role string | always |
| `job_project_id` | numeric | always |
| `job_project_path` | `group/project` | always |
| `job_namespace_id` | numeric | always |
| `job_namespace_path` | group path | always |
| `pipeline_id` | numeric | always |
| `pipeline_source` | trigger source | always |
| `job_id` | numeric | always |
| `job_source` | job source | always |
| `ref` | branch/tag name | always |
| `ref_type` | `branch` or `tag` | always |
| `ref_path` | full ref path | always |
| `ref_protected` | `true`/`false` | always |
| `branch` | branch name | when `ref_type` is `branch` |
| `sha` | commit SHA | always |
| `environment` | environment name | always |
| `environment_protected` | `true`/`false` | always |
| `deployment_tier` | tier string | always |
| `environment_action` | action string | always |
| `runner_id` | numeric | always |
| `runner_environment` | environment type | always |
| `ci_config_ref_uri` | full URI with `@ref` | always |
| `ci_config_ref_uri:host` | GitLab hostname | when valid URI |
| `ci_config_ref_uri:project_path` | `group/project` | when valid URI |
| `ci_config_ref_uri:config_path` | `.gitlab-ci.yml` path | when valid URI |
| `ci_config_ref_uri:ref` | git ref | when valid URI |
| `ci_config_sha` | SHA | always |
| `sub` | token subject | always |

## Validation flow

1. **JWT signature verification** — fetches the issuer's JWKS via OIDC discovery and verifies the token signature.
2. **Standard claim validation** — verifies `iss`, `aud`, and `exp` (30s clock leeway).
3. **Allowlist check** — enforces `allowedNamespacePaths` and/or `allowedProjectPaths` using suffix-wildcard matching.
4. **Replay detection** — the caller's replay cache prevents token reuse.

## Example configuration

```yaml
auth:
  plugins:
    - name: "gitlab-ci"
      plugin: "gitlab"
      config:
        issuerURL: "https://gitlab.com"
        audiences: ["spire-identity-exchange"]
        allowedNamespacePaths:
          - "my-org"
        allowedProjectPaths:
          - "my-org/*"
```

## Security considerations

- Use `project_id` and `namespace_id` selectors for registration entry matching rather than `project_path` / `namespace_path` — IDs are numeric and immutable across renames.
- `user_id` and `user_login` represent the human who triggered the pipeline, not the workload identity. Do not use these as sole discriminators.
- `ci_config_ref_uri` is the stable analog of GitHub's `job_workflow_ref` — prefer it over mutable display names.
- `pipeline_id`, `job_id`, and `runner_id` are ephemeral per-execution values. Do not use them for registration entry matching.
- `ref_protected` is a boolean supplement, not a sole discriminator — always pair with `ref` and `project_id`.

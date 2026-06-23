# Auth plugin: GitHub Actions OIDC "github"

Validates GitHub Actions OIDC tokens (JWTs issued by `https://token.actions.githubusercontent.com`) and generates SPIRE selectors that identify the caller by repository, workflow, branch, environment, and other GitHub-specific attributes.

Uses the generic [JWT validator](../pkg/validator/jwt/) for signature verification, key discovery, and standard claim validation (issuer, audience, expiration). Adds GitHub-specific allowlist checks (repository owner, repository name) and selector generation on top.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuerURL` | string | no | OIDC issuer. Default: `https://token.actions.githubusercontent.com`. |
| `audiences` | string array | **yes** | Expected JWT audience values. At least one entry required. |
| `allowedRepositoryOwners` | string array | see note | GitHub organizations/users allowed. Supports trailing wildcard (`*`). At least one of `allowedRepositories` or `allowedRepositoryOwners` must be set. |
| `allowedRepositories` | string array | see note | Repositories allowed in `owner/name` format. Supports trailing wildcard (`*`). At least one required if `allowedRepositoryOwners` is empty. |

When both `allowedRepositoryOwners` and `allowedRepositories` are set, the token must match **both** lists (AND logic).

## Selector reference

Selector type: `github_actions`

Selectors are generated for every non-empty claim field in the validated token:

| Selector key | Value format | Condition |
|---|---|---|
| `repository` | `owner/name` | always |
| `repository_owner` | org or user name | always |
| `repository_id` | numeric | always |
| `repository_owner_id` | numeric | always |
| `repository_visibility` | `public`, `private`, or `internal` | always |
| `workflow` | workflow display name | always |
| `workflow_ref` | `owner/repo/.github/workflows/name.yml@ref` | always |
| `workflow_ref:repo` | `owner/repo` | when `workflow_ref` has `@ref` |
| `workflow_ref:path` | `.github/workflows/name.yml` | when `workflow_ref` has `@ref` |
| `workflow_ref:ref` | git ref | when `workflow_ref` has `@ref` |
| `job_workflow_ref` | `owner/repo/.github/workflows/name.yml@ref` | always |
| `job_workflow_ref:repo` | `owner/repo` | when `job_workflow_ref` has `@ref` |
| `job_workflow_ref:path` | `.github/workflows/name.yml` | when `job_workflow_ref` has `@ref` |
| `job_workflow_ref:ref` | git ref | when `job_workflow_ref` has `@ref` |
| `ref` | full git ref | always |
| `ref_type` | `branch` or `tag` | always |
| `branch` | branch name (without `refs/heads/`) | when `ref_type` is `branch` |
| `sha` | commit SHA | always |
| `head_ref` | PR source branch | always |
| `base_ref` | PR target branch | always |
| `event_name` | trigger event | always |
| `actor` | triggering user | always |
| `actor_id` | numeric user ID | always |
| `run_id` | per-run ID | always |
| `run_number` | sequential run number | always |
| `run_attempt` | re-run attempt | always |
| `environment` | deployment environment name | always |
| `runner_environment` | `github-hosted` or `self-hosted` | always |

## Validation flow

1. **JWT signature verification** — fetches the issuer's JWKS (via OIDC discovery or explicit `jwksUri`), extracts the `kid` from the token header, and verifies the RSA/ECDSA signature.
2. **Standard claim validation** — verifies `iss`, `aud`, and `exp` (30s clock leeway).
3. **Allowlist check** — enforces `allowedRepositoryOwners` and/or `allowedRepositories` using suffix-wildcard matching.
4. **Replay detection** — the caller's replay cache (configurable `purposeMode`) prevents token reuse.

## Example configuration

```yaml
auth:
  plugins:
    - name: "github-actions"
      plugin: "github"
      config:
        issuerURL: "https://token.actions.githubusercontent.com"
        audiences: ["spire-identity-exchange"]
        allowedRepositoryOwners:
          - "my-org"
        allowedRepositories:
          - "my-org/*"
```

## Security considerations

- Use `repository_id` and `repository_owner_id` selectors for registration entry matching rather than `repository` / `repository_owner` — numeric IDs are immutable across renames and transfers.
- `actor` and `actor_id` represent the human who *triggered* the workflow, not the workload identity. Do not use these as the sole discriminator in registration entries.
- `workflow` is a mutable display name; prefer `job_workflow_ref` which is keyed on file path.
- The `head_ref` claim is attacker-controlled (PR source branch). Never use it as a sole identity discriminator.
- `run_id`, `run_number`, and `run_attempt` are ephemeral per-execution values. Do not use them for registration entry matching.

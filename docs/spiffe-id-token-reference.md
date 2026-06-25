# SPIFFE ID Derivation — Token Reference

> **Legacy mode notice:** This reference applies to the legacy server-based workflow (compiled with `-tags legacy`). In the default (agent-based) workflow, SPIFFE IDs are determined by SPIRE registration entries matching selectors — not by templates. See [docs/plugin_github.md](plugin_github.md) and related plugin docs for the selector-based approach.

A SPIFFE ID is a workload identity. The `spiffeIdTemplate` you configure in spire-identity-exchange determines
what identity a workload receives — and therefore what resources it can access. A template that
is too broad issues the same SVID to multiple distinct workloads, which is a privilege escalation
vector. A template that encodes unstable claims silently changes identity when repositories are
renamed or transferred.

This guide provides per-auth-method reference and security guidance so operators can configure
templates correctly.

> **Note:** The templates and recommendations below are suggested references, not universal rules.
> Whether a given principle applies depends on your environment and threat model. For example, some
> deployments may not require fine-grained authorization and can tolerate broader identities; others
> may run in trusted internal networks where certain uniqueness or stability guarantees are less
> critical. Use this guide as a starting point and adapt it to your specific use case.

## Core principles

| Principle | Meaning |
|---|---|
| **Uniqueness** | Distinct workloads must receive distinct SVIDs. Two workloads sharing an identity means one can impersonate the other. |
| **Claim ownership** | Every encoded claim must be controlled by the workload or its infrastructure owner — not by a human actor or a mutable display name. |
| **Stability** | The SVID must survive normal operational events: repository renames, workflow renames, pod restarts. A changed SVID silently breaks downstream policy. |
| **Predictability** | The SVID must be derivable before the workload runs, so downstream relying parties can author policy at deploy time, not at runtime. Claims that change on every run (e.g. `run_id`, `sha`) violate this. |
| **Least privilege** | Scope no broader than the access decision requires. Uniqueness is a floor, not a target. Each distinct trust boundary should produce a distinct SVID. |

---

## GitHub Actions OIDC Token

### Recommended claims

| Claim | Rationale |
|---|---|
| `ref` | Branch or tag name. Scopes identity to a deployment target. |
| `ref_type` | `branch` or `tag`. Prevents a branch named `v1.0.0` from colliding with the tag of the same name. |
| `environment` | Strongest scope signal. GitHub deployment environments support required reviewers, wait timers, and branch policies. |
| `job_workflow_ref` | Full path + ref of the *called* workflow file (e.g. `owner/repo/.github/workflows/deploy.yml@refs/heads/main`). Sigstore Fulcio encodes this as the primary SAN URI, making it the industry-canonical identity for GitHub Actions workloads. More durable than the workflow display name, but not rename-proof. Treat `.github/workflows/` paths as load-bearing infrastructure. Note: the raw value contains `/` and `@` — URL-encode if embedding in a URI path. |
| `repository_id` | Numeric, immutable. Back `repository` (slug) with this to prevent rename or transfer attacks. |
| `repository_owner_id` | Numeric, immutable. Back `repository_owner` (org name) with this. |

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `actor` / `actor_id` | Actor identity, not workload identity. Anyone who can trigger a workflow obtains the SVID regardless of branch or repo. `actor_id` is numeric but still represents the human triggering the job. |
| `workflow` | A mutable display name. Renaming the workflow file silently changes the SVID. Use `job_workflow_ref` (file path + ref) instead. |
| `run_id` / `run_number` / `run_attempt` | Ephemeral per-run values. Downstream relying parties cannot express durable policy against values that change every run. |
| `sha` | Changes on every commit. Use `ref` or `environment` for durable scoping. |
| `head_ref` | Only populated for `pull_request` events; absent on `push`. The value is the contributor's source branch name, which is attacker-controlled — a branch named `main` collides with production identity. |
| `repository` / `repository_owner` (alone) | Name-based; vulnerable to recycling after repository rename or transfer. Always back with `repository_id` / `repository_owner_id`. |

### Examples

```
spiffe://example.org/github/{{.repository_owner_id}}/{{.repository_id}}/{{.ref_type}}/{{.ref}}
spiffe://example.org/github/{{.repository_owner_id}}/{{.repository_id}}/{{.environment}}
spiffe://example.org/github/{{.repository_owner_id}}/{{.repository_id}}/{{.ref_type}}/{{.ref}}/{{.job_workflow_ref}}
```

**GitHub Enterprise:** For organizations running GitHub Enterprise, the `enterprise` claim is set by GitHub's infrastructure and reflects the enterprise slug — it is not actor-controlled or mutable by a contributor. Including it as the outermost ownership boundary is valid and adds a scoping layer above the organization:

```
spiffe://example.org/github/{{.enterprise}}/{{.repository_owner}}/{{.repository}}/{{.ref}}
```

### Anti-patterns

**Anti-pattern 1: omitting `ref` — every branch gets the same identity**
```
// UNSAFE
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}
```
A push to `main` and a PR from an external contributor both produce the same SVID.
> **Violates:** Uniqueness, Least privilege

**Anti-pattern 2: actor as workload identity**
```
// UNSAFE
spiffe://example.org/github/{{.actor}}/{{.repository_owner}}/{{.repository}}
```
Anyone who can trigger the workflow — including external contributors opening a pull request — obtains the SVID regardless of branch or workflow file.
> **Violates:** Claim ownership, Least privilege

**Anti-pattern 3: workflow display name instead of `job_workflow_ref`**
```
// FRAGILE
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}/{{.workflow}}
```
Renaming the workflow from `Deploy` to `Deploy to Production` silently changes the SVID and breaks downstream RBAC with no cryptographic signal.
> **Violates:** Stability

**Anti-pattern 4: `head_ref` for pull request workflows**
```
// UNSAFE for pull_request events
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}/{{.head_ref}}
```
`head_ref` is the attacker-controlled source branch name. A branch named `main` collides with your production identity.
> **Violates:** Claim ownership, Uniqueness

**Anti-pattern 5: slug without numeric ID**
```
// RENAME-VULNERABLE
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}/{{.ref}}
```
Both `repository_owner` and `repository` are mutable slugs. After a repo transfer or org rename, the derived SVID changes and previous grants are broken.
> **Violates:** Stability

---

## GitLab CI/CD OIDC Token

### Recommended claims

| Claim | Rationale |
|---|---|
| `project_id` | Numeric, immutable. Back all path-based claims with this. Never changes on rename or transfer. |
| `namespace_id` | Numeric group/user ID. Immutable across renames. |
| `ref` | Branch or tag name. Scopes identity to a deployment target. |
| `ref_type` | `branch` or `tag`. Prevents branch names colliding with tag names of the same value. |
| `environment` | Strongest scope signal for deployment jobs. GitLab environments support required approvers and protected branches. |
| `ci_config_ref_uri` | GitLab's analog of `job_workflow_ref`. Encodes the full path and ref of `.gitlab-ci.yml` (e.g. `gitlab.example.com/group/repo//.gitlab-ci.yml@refs/heads/main`). Available from GitLab 16.2+. Treat `.gitlab-ci.yml` paths as load-bearing infrastructure. |
| `ref_protected` *(supplementary)* | Boolean. `true` confirms the ref is a protected branch or tag. Use in combination with `ref` and `project_id` as an additional guard — not as a sole discriminator. |
| `deployment_tier` *(supplementary)* | `production`, `staging`, etc. Available from GitLab 15.2+ when a job specifies a deployment environment. Useful for environment-scoped identities. |

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `user_id` / `user_login` | Actor identity, not workload identity. Anyone who can trigger a pipeline obtains the SVID. |
| `job_id` / `pipeline_id` / `runner_id` | Ephemeral per-run values. No durable policy can be expressed against them. |
| `project_path` / `namespace_path` | Mutable display names. A project rename or group transfer silently changes the SVID. Always back with `project_id` / `namespace_id`. |
| `ci_config_sha` | Changes on every commit. Same problem as GitHub's `sha`. |
| `user_access_level` | Encodes the triggering user's project role (`developer`, `maintainer`). Human role data, not workload identity. |
| `groups_direct` | User group memberships. Human-context data, not workload identity. |

### Examples

```
spiffe://example.org/gitlab/{{.namespace_id}}/{{.project_id}}/{{.ref_type}}/{{.ref}}
spiffe://example.org/gitlab/{{.namespace_id}}/{{.project_id}}/{{.environment}}
spiffe://example.org/gitlab/{{.namespace_id}}/{{.project_id}}/{{.ref_type}}/{{.ref}}/{{.ci_config_ref_uri}}
```

### Anti-patterns

**Anti-pattern 1: path instead of ID — rename breaks identity**
```
// FRAGILE
spiffe://example.org/gitlab/{{.namespace_path}}/{{.project_path}}/{{.ref}}
```
Renaming the group or project silently changes the SVID. Use `namespace_id`/`project_id`.
> **Violates:** Stability

**Anti-pattern 2: user as discriminator**
```
// UNSAFE
spiffe://example.org/gitlab/{{.user_login}}/{{.project_id}}
```
Any contributor who can trigger a pipeline gets this SVID, regardless of branch.
> **Violates:** Claim ownership, Least privilege

**Anti-pattern 3: omitting `ref_type`**
```
// AMBIGUOUS
spiffe://example.org/gitlab/{{.namespace_id}}/{{.project_id}}/{{.ref}}
```
A branch named `v1.0.0` collides with the tag `v1.0.0`. Always include `ref_type`.
> **Violates:** Uniqueness

**Anti-pattern 4: `sub` directly**
```
// FRAGILE
spiffe://example.org/gitlab/{{.sub}}
```
GitLab's default `sub` is `project_path:{group}/{project}:ref_type:{type}:ref:{branch}` — fully name-based. Any rename changes the `sub`. Derive identity from `project_id` and `namespace_id` instead.
> **Violates:** Stability

---

## Kubernetes Bound Service Account Tokens

### Recommended claims

| Claim | Rationale |
|---|---|
| `namespace` | Kubernetes namespace. Scopes identity to a tenant boundary. Required to disambiguate service accounts with the same name in different namespaces. |
| `serviceaccount/name` | Service account name within the namespace. |
| `serviceaccount/uid` | Immutable UID. Prevents identity reuse if the SA is deleted and recreated with the same name — deletion changes the UID. |
| `pod/uid` | For per-pod identity. Pod UIDs are never reused by the Kubernetes garbage collector. |
| `pod-owner-uid` | UID of the controlling owner object (e.g. a ReplicaSet or StatefulSet). More stable than `pod/uid` for workload identity because the owner persists across pod restarts. |
| `node/uid` | For node-level workload attestation. |

> **Critical caveat.** Node information in BSATs (`kubernetes.io/node/name`, `kubernetes.io/node/uid`) is **not verified** by the Kubernetes API server during authentication. It is included as informational metadata only. Do not use node claims as security-critical identity anchors without additional out-of-band verification.

> **Cluster name** must be derived from the verified OIDC issuer URL, not from a claim inside the token that a workload can supply.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `pod/name` | Ephemeral. Redeployments produce a new pod with a new name. No durable policy can reference it. |
| `node/name` | Node hostnames can be reassigned. Back with `node/uid`. Also: not API-server-verified (see caveat above). |
| `serviceaccount/name` without `namespace` | Service account names are only unique within a namespace. `default/myapp` and `prod/myapp` are different workloads. |
| `sub` (raw) | The `sub` claim is `system:serviceaccount:<namespace>:<name>` — name-based. If the SA is deleted and recreated with the same name, `sub` is identical but `serviceaccount/uid` changes. |

### Examples

```
spiffe://example.org/k8s/{{.clusterName}}/{{.namespace}}/{{.serviceAccountName}}/{{.serviceAccountUID}}
spiffe://example.org/k8s/{{.clusterName}}/{{.namespace}}/{{.serviceAccountName}}/{{.podUID}}
```

### Anti-patterns

**Anti-pattern 1: namespace alone**
```
// UNSAFE
spiffe://example.org/k8s/{{.clusterName}}/{{.namespace}}
```
Every service account in the namespace gets the same SVID.
> **Violates:** Uniqueness, Least privilege

**Anti-pattern 2: name without UID — SA reuse**
```
// VULNERABLE TO REUSE
spiffe://example.org/k8s/{{.clusterName}}/{{.namespace}}/{{.serviceAccountName}}
```
If the SA is deleted and recreated with the same name, the new SA inherits the old SVID's grants. Add `serviceaccount/uid` to bind to the specific object.
> **Violates:** Uniqueness

**Anti-pattern 3: pod name as durable identity**
```
// FRAGILE
spiffe://example.org/k8s/{{.clusterName}}/{{.namespace}}/{{.podName}}
```
Pod names change on every restart for Deployments. Use `pod/uid` or `pod-owner-uid` if pod-level granularity is needed.
> **Violates:** Stability, Predictability

---

## AWS (EC2 IID, EKS IRSA, ECS)

### Recommended claims

| Source | Claim | Rationale |
|---|---|---|
| EC2 IID | `accountId` | Scopes identity to an AWS account boundary. Always required — instance IDs are not globally unique across accounts. |
| EC2 IID | `region` | Instance IDs are unique per account per region. |
| EC2 IID | `instanceId` | Stable for the lifetime of the EC2 instance. |
| EC2 IID | `instanceProfileArn` *(selector, not path)* | Binds to the IAM role attached to the instance. Use as a scoping *selector* rather than a SPIFFE ID path component — the role name embedded in the ARN is a mutable string. |
| ECS | `taskDefinitionFamily` | Identifies the workload type durably across task restarts. |
| EKS IRSA | `accountId` + `sub` (`system:serviceaccount:<ns>:<name>`) | OIDC-federated SA identity. |

> **ECS note.** ECS tasks receive IAM credentials via the container credentials endpoint, not a standard OIDC token. The `taskDefinitionFamily` + task ARN pattern is a community convention without an authoritative standard.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `privateIp` | RFC 1918 addresses are not globally unique and are reassigned when instances are terminated and replaced. |
| `instanceId` without `accountId` | Instance IDs are unique per account per region, not globally. |
| `availabilityZone` | AZ names are not globally unique across AWS accounts. Infrastructure topology, not workload identity. |
| `region` alone | Too broad. Every workload in the region shares the identifier. |
| `imageId` (AMI ID) | Identifies the machine image, not the running workload. All instances from the same AMI share the same `imageId`. |
| `pendingTime` | Updated on every instance start/stop cycle. Ephemeral. |

### Examples

```
spiffe://example.org/aws/ec2/{{.accountId}}/{{.region}}/{{.instanceId}}
spiffe://example.org/aws/ecs/{{.accountId}}/{{.taskFamily}}
spiffe://example.org/aws/ecs/{{.accountId}}/{{.region}}/{{.taskFamily}}
spiffe://example.org/aws/eks/{{.accountId}}/{{.clusterName}}/{{.namespace}}/{{.serviceAccount}}
```

For ECS, include `region` only if you need to issue different credentials per region (e.g. the prod region gets write access, others read-only). If the same task family deploys identically across regions and needs the same permissions everywhere, omit `region` to avoid duplicating policy per region for what is logically one workload.

### Anti-patterns

**Anti-pattern 1: IP address as identity**
```
// UNSAFE
spiffe://example.org/aws/{{.accountId}}/{{.privateIp}}
```
IPs are recycled. A new instance that gets the same private IP as a terminated one inherits its access grants.
> **Violates:** Uniqueness, Stability

**Anti-pattern 2: AMI as workload identity**
```
// WRONG ABSTRACTION
spiffe://example.org/aws/{{.accountId}}/{{.imageId}}
```
All instances built from the same AMI — dev, staging, prod — receive identical SVIDs.
> **Violates:** Uniqueness, Least privilege

**Anti-pattern 3: AZ as scope**
```
// NOT GLOBALLY UNIQUE
spiffe://example.org/aws/{{.accountId}}/{{.availabilityZone}}
```
AZ names are not globally unique across AWS accounts. `us-east-1a` in one account is a different physical AZ from `us-east-1a` in another.
> **Violates:** Uniqueness, Least privilege

---

## Google Cloud (GCE, GKE Workload Identity)

### Recommended claims

| Source | Claim | Rationale |
|---|---|---|
| GCE | `project_number` | Numeric, immutable. `project_id` (string) is a mutable display name that can be changed by the owner. Always prefer `project_number` for SPIFFE ID derivation. |
| GCE | `instance_id` | Numeric VM instance ID. Stable for the lifetime of the VM. |
| GKE WI | `sub` (numeric SA format) | The `sub` in a GCE identity token contains the numeric service account ID — stable and immutable. Prefer over SA `email` which is mutable. |
| GKE WI | Kubernetes SA `uid` | OIDC-federated SA identity. The SA UID is stable even if the SA name changes. |

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `project_id` (string display name) | Mutable. Projects can be renamed by the owner. Always use `project_number` for durability. |
| `zone` | Infrastructure topology, not workload identity. Encodes zone in the SPIFFE ID creates identity drift when instances migrate across zones. |
| User account `email` | Person identity, not workload identity. Service account emails are mutable too (the SA can be renamed). |
| `instance_name` | Mutable. VM names can be reused across zones. The GCE token docs explicitly warn: "instance_name can be reused across zones." Use `instance_id`. |

### Examples

```
spiffe://example.org/gcp/gce/{{.projectNumber}}/{{.instanceId}}
spiffe://example.org/gcp/gke/{{.projectNumber}}/{{.clusterName}}/{{.namespace}}/{{.serviceAccountUID}}
```

### Anti-patterns

**Anti-pattern 1: string project ID instead of project number**
```
// FRAGILE
spiffe://example.org/gcp/{{.projectId}}/{{.instanceId}}
```
String project IDs (`my-project-prod`) can be changed by the project owner. All downstream RBAC silently breaks on rename.
> **Violates:** Stability

**Anti-pattern 2: zone-scoped identity**
```
// TOO BROAD
spiffe://example.org/gcp/{{.projectNumber}}/{{.zone}}
```
Every VM in the zone shares the same SVID.
> **Violates:** Uniqueness, Least privilege

**Anti-pattern 3: service account email**
```
// MUTABLE
spiffe://example.org/gcp/{{.projectNumber}}/{{.serviceAccountEmail}}
```
Service account emails contain the project ID string (mutable) and the SA name (mutable). Use the numeric `sub` from the GCE identity token instead.
> **Violates:** Stability

---

## Azure (Workload Identity, Managed Identity)

### Recommended claims

| Claim | Rationale |
|---|---|
| `tid` | Tenant ID GUID. Always required as the outermost scope boundary. `sub` is only unique within a tenant — must always be paired with `tid`. |
| `oid` | Object ID GUID of the principal. Immutable and globally unique when paired with `tid`. Microsoft explicitly recommends `oid + tid` as the stable cross-application identifier, *not* `sub` (which is pairwise and application-specific in some token types). |
| `appid` / `azp` | Client/application ID GUID. Stable per app registration. Use for application-level identity. `appid` in v1 tokens, `azp` in v2. |
| `xms_mirid` *(supplementary)* | Managed identity resource ID. Encodes subscription, resource group, and identity name. Useful for scoping to a specific managed identity resource. Caution: the path within `xms_mirid` contains mutable human-readable strings (resource group name, identity name). Use `oid` as the primary anchor; treat `xms_mirid` as supplementary scope. |
| `vm_id` | Azure VM resource GUID from Azure Resource Manager. Immutable unique VM identifier. More stable than `vm_name`. |

> **`sub` pairwise behaviour.** In Azure AD, `sub` is documented as "consistent within a single tenant" but is *pairwise* for some token types — the value varies per application registration. Microsoft explicitly states `sub` alone is not a globally unique identifier and recommends `oid + tid` for cross-application stable identity.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| Display names (app name, UMI name, SP display name) | Mutable. Renaming via the portal or API silently changes the derived SVID. |
| `sub` without `tid` | `sub` is tenant-scoped and may be pairwise. Two tenants can have principals that produce the same `sub`. Always pair with `tid`. |
| `upn` / `email` | User identity, not workload identity. |
| Subscription ID alone | A billing/resource boundary shared by thousands of workloads. |
| `vm_name` | Mutable VM display name. Should not appear in SPIFFE ID path templates. |

### Examples

```
spiffe://example.org/azure/{{.tenantId}}/{{.objectId}}
spiffe://example.org/azure/{{.tenantId}}/{{.appId}}
spiffe://example.org/azure/{{.tenantId}}/{{.subscriptionId}}/{{.vmId}}
```

### Anti-patterns

**Anti-pattern 1: display name instead of object ID**
```
// FRAGILE
spiffe://example.org/azure/{{.tenantId}}/{{.appDisplayName}}
```
Renaming the app registration in Entra ID silently changes the SVID.
> **Violates:** Stability

**Anti-pattern 2: `sub` without tenant**
```
// NOT GLOBALLY UNIQUE
spiffe://example.org/azure/{{.sub}}
```
`sub` is pairwise and tenant-scoped. Two tenants can produce principals with the same `sub`. Always prefix with `tid`.
> **Violates:** Uniqueness

**Anti-pattern 3: `xms_mirid` as sole anchor**
```
// CONTAINS MUTABLE NAMES
spiffe://example.org/azure/{{.tenantId}}/{{.xms_mirid}}
```
`xms_mirid` embeds the resource group name and identity name — both mutable strings. Use `oid` as the primary anchor.
> **Violates:** Stability

---

## CircleCI OIDC Token

### Recommended claims

| Claim | Rationale |
|---|---|
| `aud` (org UUID) | Stable UUID for the CircleCI organization. Always validate to prevent token reuse across organisations. |
| `oidc.circleci.com/project-id` | Stable UUID for the project. Immutable across project renames. CircleCI docs recommend this as "the most secure and direct way" to scope access. |
| `oidc.circleci.com/context-ids` | UUIDs of contexts granted to this job. Contexts gate secret access; encoding them narrows scope to jobs that have been granted the required context. |
| `oidc.circleci.com/pipeline-definition-id` | UUID for the pipeline definition (`.circleci/config.yml`). The stable analog of `job_workflow_ref` / `ci_config_ref_uri`. More durable than `pipeline-id` (per-run) or `workflow-id` (per-run). |

> **v1 vs v2 token note.** CircleCI provides `$CIRCLE_OIDC_TOKEN` (v1) and `$CIRCLE_OIDC_TOKEN_V2`. The v2 token adds `vcs-origin` (repository URL) and `vcs-ref` (branch/tag reference) to the `sub` claim. For branch-scoped SPIFFE IDs, the v2 token's `vcs-ref` is useful — but treat it like GitHub's `ref`: anchor it to `project-id` and do not use it alone.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| User ID (in `sub`) | The v1 `sub` is `org/<org_id>/project/<project_id>/user/<user_id>`. The user segment is actor identity. Two different users triggering the same workflow produce different SVIDs — that is actor identity, not workload identity. |
| `oidc.circleci.com/pipeline-id` | Per-run UUID. Ephemeral. Distinct from `pipeline-definition-id` (stable). |
| `oidc.circleci.com/job-id` | Per-execution UUID. Ephemeral. |
| `oidc.circleci.com/workflow-id` | Per-run UUID. Ephemeral. |
| Project name / context name | Mutable display names. Use the UUID equivalents. |

### Examples

```
spiffe://example.org/circleci/{{.orgId}}/{{.projectId}}
spiffe://example.org/circleci/{{.orgId}}/{{.projectId}}/{{.contextId}}
spiffe://example.org/circleci/{{.orgId}}/{{.projectId}}/{{.pipelineDefinitionId}}
```

### Anti-patterns

**Anti-pattern 1: using the full v1 `sub` as-is**
```
// CONTAINS ACTOR IDENTITY
spiffe://example.org/circleci/{{.sub}}
```
The v1 `sub` contains the triggering user's UUID. Two different users triggering the same project workflow produce different SVIDs. Derive identity from `project-id` and `context-ids` instead.
> **Violates:** Claim ownership

**Anti-pattern 2: per-run IDs**
```
// EPHEMERAL
spiffe://example.org/circleci/{{.orgId}}/{{.pipelineId}}/{{.workflowId}}
```
Both `pipeline-id` and `workflow-id` are per-run UUIDs. No relying party can express durable policy against them.
> **Violates:** Predictability

---

## Terraform Cloud / Enterprise OIDC Token

### Recommended claims

| Claim | Rationale |
|---|---|
| `terraform_organization_id` | Stable UUID for the TFC organization. The TFC documentation explicitly warns: if you do not match against at least the organization ID, any workspace on HCP Terraform can access your resources. |
| `terraform_workspace_id` | Stable UUID for the workspace. Immutable across workspace renames. |
| `terraform_project_id` | Stable UUID for the TFC project (the organizational grouping above workspaces). Use for multi-project scoping. |
| `terraform_run_phase` | `plan` or `apply`. The primary least-privilege lever in TFC: issue read-only credentials on `plan`, write credentials on `apply` only. |

> **`sub` claim note.** The Terraform Cloud `sub` claim contains the fully qualified workspace path: `organization:<org_name>:project:<project_name>:workspace:<workspace_name>:run_phase:<phase>`. This is entirely name-based and mutable. The TFC documentation explicitly warns to use `*_id` fields instead of `sub` or `*_name` fields for stable identity binding.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `terraform_workspace_name` | Mutable display name. Renaming the workspace silently changes the SVID and breaks all downstream grants. Always use `terraform_workspace_id`. |
| `terraform_organization_name` | Mutable. Use `terraform_organization_id`. |
| `terraform_project_name` | Mutable. Use `terraform_project_id`. |
| `terraform_run_id` | Per-run value. Stable within a single run's lifetime but unique per run — no durable policy can reference it. |
| `terraform_full_provider_address` | Identifies the Terraform provider plugin, not the workload. |
| `terraform_full_workspace` | Full workspace path string including org and project names — all mutable. Avoid for the same reason as `*_name` fields. |
| `sub` (raw) | Entirely name-based. See note above. |

### Examples

```
spiffe://example.org/tfc/{{.orgId}}/{{.projectId}}/{{.workspaceId}}/{{.runPhase}}
```

### Anti-patterns

**Anti-pattern 1: workspace name instead of ID**
```
// FRAGILE
spiffe://example.org/tfc/{{.terraform_organization_name}}/{{.terraform_workspace_name}}
```
Renaming `prod-deploy` to `production-deploy` silently revokes all credentials the workspace held.
> **Violates:** Stability

**Anti-pattern 2: omitting `run_phase` — plan gets write access**
```
// OVERPRIVILEGED
spiffe://example.org/tfc/{{.orgId}}/{{.workspaceId}}
```
Plan runs, which may execute code from pull requests, receive the same SVID as apply runs. Always encode `run_phase` and restrict write credentials to `apply`.
> **Violates:** Least privilege

**Anti-pattern 3: `sub` as identity anchor**
```
// NAME-BASED, FULLY MUTABLE
spiffe://example.org/tfc/{{.sub}}
```
Every component of the TFC `sub` is a human-readable name. Any rename silently changes the SVID.
> **Violates:** Stability

---

## Bitbucket Pipelines OIDC Token

### Recommended claims

| Claim | Rationale |
|---|---|
| `workspaceUuid` | Stable UUID for the Bitbucket workspace. Immutable across workspace renames. |
| `repositoryUuid` | Stable UUID for the repository. Immutable across repository renames and workspace transfers. |
| `branchName` | Scopes identity to a specific branch. Use only for pipelines triggered by `push` events on durable branch names (`main`, `release/*`). Do not use for PR pipelines (see anti-patterns). |
| `deploymentEnvironment` | UUID for a Pipelines deployment environment. Strongest scope signal for deployment jobs. Note: the claim name in the JWT is `deploymentEnvironment`, not `deploymentEnvironmentUuid`. |

> **`sub` claim format.** The Bitbucket OIDC `sub` is `{REPOSITORY_UUID}[:{ENVIRONMENT_UUID}]:{STEP_UUID}`. The environment UUID is only included when the step is assigned to a deployment environment. The trailing `STEP_UUID` is **per-execution ephemeral**. Do not use `sub` directly in SPIFFE ID templates — extract the stable UUIDs from the dedicated top-level claims instead.

> **`aud` validation.** Always validate the `aud` claim (workspace-scoped identifier) to prevent tokens issued by one workspace from being accepted by another workspace's relying party.

### Claims to never use as sole discriminator

| Claim | Why |
|---|---|
| `pipelineUuid` | Per-run UUID. Ephemeral. |
| `stepUuid` | Per-execution UUID. Ephemeral. Also embedded in `sub` — another reason not to use `sub` directly. |
| Repository or workspace slug/name | Mutable display names. Back with UUID equivalents. |
| `branchName` for PR pipelines | The source branch is contributor-controlled. A contributor can name their branch `main` to collide with a production identity. |

### Examples

```
spiffe://example.org/bitbucket/{{.workspaceUuid}}/{{.repositoryUuid}}
spiffe://example.org/bitbucket/{{.workspaceUuid}}/{{.repositoryUuid}}/{{.branchName}}
spiffe://example.org/bitbucket/{{.workspaceUuid}}/{{.repositoryUuid}}/{{.deploymentEnvironment}}
```

### Anti-patterns

**Anti-pattern 1: repository slug instead of UUID**
```
// FRAGILE
spiffe://example.org/bitbucket/{{.workspaceSlug}}/{{.repositorySlug}}
```
Repository renames and workspace transfers change the slug. Use UUIDs.
> **Violates:** Stability

**Anti-pattern 2: `sub` directly**
```
// CONTAINS EPHEMERAL stepUuid
spiffe://example.org/bitbucket/{{.sub}}
```
The `sub` contains the per-execution `stepUuid` as its final segment. Every pipeline step produces a different SVID.
> **Violates:** Predictability

**Anti-pattern 3: `branchName` on PR pipelines**
```
// UNSAFE for pull request pipelines
spiffe://example.org/bitbucket/{{.workspaceUuid}}/{{.repositoryUuid}}/{{.branchName}}
```
A contributor's PR from a branch named `main` collides with your production identity. Restrict `branchName` to push-triggered pipelines on protected branches.
> **Violates:** Claim ownership, Uniqueness

---

## Cross-cutting rules

| Rule | Rationale |
|---|---|
| Prefer immutable IDs over mutable display names | Any claim labeled "name", "slug", "display", or "path" is suspect. Every provider studied has a numeric or UUID equivalent that is rename-proof. |
| Always include a scope boundary as the outermost segment | `accountId`, `tenantId`, `orgId`, `project_number`. Without it, IDs from different tenants/accounts can collide. |
| Never use actor/user claims as workload identity | Who triggered the job is not what the job is. Actor claims allow privilege escalation by anyone who can trigger a pipeline. |
| Never use ephemeral per-run claims | `run_id`, `job_id`, `pipeline_id`, `step_id`. No downstream policy can durably reference them. |
| Separate plan-equivalent from apply-equivalent phases | Where the token includes a phase claim (Terraform `run_phase`, GitHub separate workflow triggers), encode it and issue least-privilege credentials per phase. |
| Back name-based claims with ID-based claims | If you include a human-readable segment for debuggability, pair it with the immutable ID that is the actual identity anchor. |
| Validate `aud` always | The `aud` claim scopes the token to its intended recipient. Failing to validate it allows tokens issued for one service to be replayed against another. |
| Do not use `sub` directly without understanding its format | Every provider formats `sub` differently. Several (Azure, CircleCI v1, Bitbucket) embed actor data or ephemeral values in `sub`. Parse the stable claims from dedicated top-level fields instead. |

---

## Token formats and verification

### Token type by provider

| Provider | Token type | JWT? |
|---|---|---|
| GitHub Actions OIDC | OIDC ID token | Yes |
| GitLab CI/CD OIDC | OIDC ID token | Yes |
| Kubernetes Bound SA Token | Projected service account token | Yes |
| EKS IRSA | OIDC ID token | Yes |
| GKE Workload Identity (ID token) | OIDC ID token | Yes |
| Azure Workload / Managed Identity | Azure AD JWT | Yes |
| CircleCI OIDC | OIDC ID token | Yes |
| Terraform Cloud OIDC | OIDC ID token | Yes |
| Bitbucket Pipelines OIDC | OIDC ID token | Yes |
| **AWS EC2 Instance Identity Document** | JSON + PKCS#7 signature | **No** |
| **GCE / Google OAuth2 access token** | Opaque token | **No** |
| **ECS task credentials** | STS-style key/secret/session token | **No** |

### Verification methods

**OIDC JWTs (all providers except AWS EC2 IID, GCE access token, ECS)**

Can be verified **offline** without a live API call:

1. Fetch the provider's JWKS endpoint (e.g. `https://token.actions.githubusercontent.com/.well-known/jwks`).
2. Validate the signature locally using the published public key.
3. Verify `iss`, `aud`, and `exp` claims.

This is the approach SPIFFE/SPIRE uses — it trusts the OIDC issuer's published keys rather than making a runtime API call per token.

**AWS EC2 Instance Identity Document**

Not a JWT. The IID is a JSON document with a detached PKCS#7 signature:

- Verify the signature against [AWS's published RSA certificate](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html) (region-specific) — no API call required.
- Alternatively, call `ec2:DescribeInstances` to cross-check the metadata, but this requires AWS credentials on the verifier side.

**GCE / Google OAuth2 access token (opaque)**

Cannot be decoded locally — must be introspected via Google's tokeninfo endpoint or the Google API. For SPIFFE ID derivation, prefer requesting a **GCE identity token** (a standard OIDC JWT) from the metadata server instead.

**ECS task credentials (STS-style)**

Access key + secret + session token. The session token is opaque. Verify identity by calling AWS STS `GetCallerIdentity` — there is no offline verification path.

### Summary

| Verification path | Providers |
|---|---|
| Offline (JWKS signature) | GitHub Actions, GitLab, Kubernetes BSAT, EKS IRSA, GKE WI ID token, Azure, CircleCI, Terraform Cloud, Bitbucket |
| Offline (PKCS#7 against published cert) | AWS EC2 IID |
| Requires live API call | GCE OAuth2 access token (tokeninfo), ECS (STS GetCallerIdentity) |

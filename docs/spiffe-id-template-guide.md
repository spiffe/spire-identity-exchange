# SPIFFE ID Template Guide

> **Legacy mode notice:** This guide applies to the legacy server-based workflow (compiled with `-tags legacy`). In the default (agent-based) workflow, SPIFFE IDs are determined by SPIRE registration entries matching selectors — not by templates. See [docs/plugin_github.md](plugin_github.md) and related plugin docs for the selector-based approach.

A SPIFFE ID is a workload identity. The `spiffeIdTemplate` you configure in spire-identity-exchange determines
what identity a workload receives — and therefore what resources it can access. A template that
is too broad issues the same SVID to multiple distinct workloads, which is a privilege escalation
vector. A template that encodes unstable claims silently changes identity when repositories are
renamed or transferred.

This guide provides per-auth-method reference and security guidance so operators can configure
templates correctly.

## Core principles

| Principle | Meaning |
|---|---|
| **Uniqueness** | Distinct workloads must receive distinct SVIDs. Two workloads sharing an identity means one can impersonate the other. |
| **Claim ownership** | Every encoded claim must be controlled by the workload or its infrastructure owner — not by a human actor or a mutable display name. |
| **Stability** | The SVID must survive normal operational events: repository renames, workflow renames, pod restarts. A changed SVID silently breaks downstream policy. |
| **Predictability** | The SVID must be derivable before the workload runs, so downstream relying parties can author policy at deploy time, not at runtime. Claims that change on every run (e.g. `run_id`, `sha`) violate this. |
| **Least privilege** | Scope no broader than the access decision requires. Uniqueness is a floor, not a target. Each distinct trust boundary should produce a distinct SVID. |

---

## GitHub Actions OIDC

GitHub Actions workflows request a short-lived OIDC token from GitHub's token service
(`https://token.actions.githubusercontent.com`). The full claim reference is available at
https://docs.github.com/en/actions/reference/openid-connect-reference.

### Claim inventory

| Claim | Description | Stability | Example value |
|---|---|---|---|
| `sub` | GitHub-constructed composite identity. Structure depends on job context (see below). | Stable | `repo:myorg/myrepo:ref:refs/heads/main` |
| `iss` | Token issuer. Always `https://token.actions.githubusercontent.com`. | Stable | — |
| `aud` | Audience. Set by the workflow when requesting the token. | Operator-defined | `spire-identity-exchange` |
| `repository` | Full repository name in `owner/name` format. | Name-stable; changes on transfer or rename | `myorg/myrepo` |
| `repository_id` | Immutable numeric ID of the repository. Survives renames and transfers. | Permanent | `987654321` |
| `repository_owner` | Organization or user that owns the repository. | Name-stable; changes on transfer | `myorg` |
| `repository_owner_id` | Immutable numeric ID of the owner. | Permanent | `12345678` |
| `repository_visibility` | `public`, `private`, or `internal`. | Stable | `private` |
| `ref` | Full git ref that triggered the workflow, including the `refs/heads/` or `refs/tags/` prefix. | Stable | `refs/heads/main` |
| `ref_type` | `branch` or `tag`. | Stable | `branch` |
| `ref_protected` | `true` if the ref has branch protection rules enabled. | Stable | `true` |
| `sha` | Commit SHA. Unique per commit. | Changes every push | `abc1234...` |
| `environment` | GitHub Actions deployment environment name. **Only present when the job references a named environment.** | Stable if environment exists | `production` |
| `environment_node_id` | Immutable node ID of the environment object. | Permanent | `EN_xxx` |
| `job_workflow_ref` | File path and ref of the **executing** workflow. The primary identity signal for what code is running. | Stable (keyed on file path, not display name) | `myorg/myrepo/.github/workflows/deploy.yml@refs/heads/main` |
| `job_workflow_sha` | Commit SHA of the executing workflow file. | Changes every push | `def5678...` |
| `workflow_ref` | File path and ref of the **calling** workflow (differs from `job_workflow_ref` when reusable workflows are involved). | Stable | `myorg/myrepo/.github/workflows/caller.yml@refs/heads/main` |
| `workflow` | Display name of the workflow. **Mutable** — changes if the workflow is renamed. | Mutable | `Deploy to Production` |
| `event_name` | Event that triggered the workflow run. | Stable | `push` |
| `actor` | Username of the human or bot that triggered the job. **Not workload identity.** | Mutable (username can be changed) | `octocat` |
| `actor_id` | Immutable numeric ID of the actor. | Permanent | `1234567` |
| `run_id` | Unique identifier for this workflow run. Never reused for a given repository. | Ephemeral | `1234567890` |
| `run_number` | Sequential run counter for this workflow in this repository. Resets on transfer. | Ephemeral | `42` |
| `run_attempt` | Re-run attempt number (1 on first run). | Ephemeral | `1` |
| `runner_environment` | `github-hosted` or `self-hosted`. | Stable | `github-hosted` |
| `head_ref` | Source branch of a pull request. **Controlled by the PR submitter.** Only present on `pull_request` events. | External | `feature/login` |
| `base_ref` | Target branch of a pull request. Only present on `pull_request` events. | Stable | `main` |
| `workflow_sha` | Commit SHA of the calling workflow file. | Changes every push | `abc1234...` |
| `repo_property_*` | Custom repository properties defined at the organization or enterprise level, prefixed with `repo_property_`. Enables attribute-based access control without hardcoding repo names. | Stable while property exists | `repo_property_team=platform` |

### Template variables vs. raw claims

The table above lists JWT **claims** as the GitHub OIDC issuer emits them. spire-identity-exchange
**rewrites and sanitizes** some of these before exposing them to the SPIFFE ID template, so the
template variable does NOT always match the raw claim:

| Template variable | Source | Sanitized? | Notes |
|---|---|---|---|
| `{{.repository}}` | repo portion of the `repository` claim (after the slash) | yes — lowercased, non-`[a-z0-9-]` replaced with `-` | **Not the raw `owner/name`.** Using just `{{.repository}}` collapses identities across orgs (`acme/app` and `globex/app` both become `app`). Pair with `{{.org}}` or `{{.repository_owner}}`. |
| `{{.org}}` | owner portion of the `repository` claim (before the slash) | yes | Convenience alias for `{{.repository_owner}}`. |
| `{{.repository_owner}}` | raw `repository_owner` claim | no | Use this when you want the owner name unmodified. |
| `{{.ref}}` | `ref` claim with `refs/heads/` / `refs/tags/` prefix stripped, then sanitized | yes | Use `{{.ref_type}}` alongside to distinguish branch vs. tag. |
| `{{.workflow}}` / `{{.workflow_ref}}` / `{{.job_workflow_ref}}` / `{{.sha}}` / `{{.actor}}` / `{{.runner_environment}}` / `{{.run_id}}` / `{{.run_number}}` | matching JWT claim | yes — lowercased, non-`[a-z0-9-]` replaced with `-` | Sanitization is required to produce a valid SPIFFE path segment. |
| `{{.trust_domain}}` | configured `spire.trustDomain` | n/a | Constant per service instance; not from the JWT. |
| any other claim, e.g. `{{.environment}}` | raw JWT claim | no | Available unmodified via `{{.claimName}}`. Use sparingly — special characters in raw claims may produce invalid SPIFFE IDs. |

Rule of thumb: when in doubt about whether a template variable is sanitized, dump the rendered
SPIFFE ID at config-validation time against a sample token.

### The `sub` claim

GitHub constructs `sub` as a composite string. Its structure depends on the job context:

| Job context | `sub` value |
|---|---|
| Branch-triggered | `repo:myorg/myrepo:ref:refs/heads/main` |
| Tag-triggered | `repo:myorg/myrepo:ref:refs/tags/v1.0.0` |
| Environment-gated job | `repo:myorg/myrepo:environment:production` |
| Pull request | `repo:myorg/myrepo:pull_request` |

`sub` is the claim most cloud providers (AWS IAM, GCP Workload Identity) use as the primary
trust condition for GitHub OIDC federation. It is a single claim that encodes ownership, scope,
and context — but at the cost of readability and structured path composition. For spire-identity-exchange,
encoding individual claims as structured path segments is generally preferable to relying on the
composite `sub` string.

### Recommended claims for encoding in the SPIFFE ID

Organize your template around three layers:

**Layer 1 — Ownership** (who controls this code)

Use `repository_owner_id` rather than `repository_owner`. If an organization is deleted and
another party claims the same name, a name-based SVID would be issued to the wrong workload.
Numeric IDs are permanent and cannot be reused.

> This is the same guidance GCP Workload Identity Federation gives for attribute conditions:
> *"Using 'name' fields like `repository` and `repository_owner` increases the chances of
> cybersquatting and typosquatting attacks. Use the numeric `*_id` fields instead, which are
> unique and can't be reused."*
> — [GCP: Workload Identity Federation with deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)

If human readability in SPIFFE IDs is important, include the name-based field alongside the ID,
or include the ID as a `requiredClaims` gate (see below).

**Layer 2 — Execution scope** (where/when this runs)

Use `ref` for branch/tag-scoped identity. For jobs that run in a GitHub Actions deployment
environment, use `environment` — it is the strongest scope signal because deployment environments
support required reviewers, wait timers, and branch policies.

**Layer 3 — Workflow identity** (what is running)

Use `job_workflow_ref`. This is the approach taken by [Sigstore Fulcio](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/),
which encodes `job_workflow_ref` as the primary SAN URI in code-signing certificates — the
industry's clearest statement that workflow file path is the canonical identity of a GitHub
Actions workload. It is keyed on the file path, so it is stable across workflow renames.

### Claims to never use as the sole identity discriminator

| Claim | Why |
|---|---|
| `actor` / `actor_id` | Represents the human or bot who *triggered* the job. Identity of the triggering person is not workload identity. A contributor who can trigger a workflow obtains the SVID regardless of branch or repo. |
| `workflow` | A mutable display name. Renaming the workflow silently changes the SVID and breaks downstream policy. Use `job_workflow_ref` (file path) instead. |
| `run_id` / `run_number` / `run_attempt` | Ephemeral per-run values. Downstream relying parties cannot express durable policy against a value that changes every run. |
| `sha` | Changes on every commit. Relying parties must update policy after every push. Use `ref` or `environment` for durable scoping. |
| `head_ref` | Controlled by the PR submitter. A contributor can name their branch `main` or `release/prod` to collide with a privileged identity. |
| `repository` / `repository_owner` (alone) | Name-based; vulnerable to recycling after repository transfer or deletion. Back with `repository_id` / `repository_owner_id`. |

### Canonical reference templates

**Minimum safe template** — ownership + branch scope:

```
spiffe://{{.trust_domain}}/github/{{.repository_owner}}/{{.repository}}/ref/{{.ref}}
```

Pair with `requiredClaims: ["repository_owner_id", "repository_id", "ref"]` to enforce numeric
ID presence even though the path uses human-readable names.

**Recommended for CI workloads** — adds workflow file identity, distinguishing `ci.yml` from `deploy.yml`:

```
spiffe://{{.trust_domain}}/github/{{.repository_owner}}/{{.repository}}/ref/{{.ref}}/wf/{{.job_workflow_ref}}
```

**Recommended for production deployments** — ties identity to an approval-gated environment:

```
spiffe://{{.trust_domain}}/github/{{.repository_owner}}/{{.repository}}/env/{{.environment}}
```

> **Warning:** `environment` is only present in tokens issued for jobs that reference a GitHub
> Actions deployment environment. Always pair this template with
> `requiredClaims: ["environment"]` so tokens without this claim are rejected rather than
> producing a malformed SPIFFE ID.

### Recommended `requiredClaims` configuration

| Template used | Recommended `requiredClaims` |
|---|---|
| Minimum (ref-based) | `["repository_owner_id", "repository_id", "ref"]` |
| CI workload (ref + workflow) | `["repository_owner_id", "repository_id", "ref", "job_workflow_ref"]` |
| Production deploy (environment) | `["repository_owner_id", "repository_id", "environment"]` |

The `*_id` claims in `requiredClaims` act as a stability gate even when the template encodes
the human-readable name — a token that lacks the numeric ID is rejected.

### Common anti-patterns

**Anti-pattern 1: omitting `ref` — every branch gets the same identity**

```
// UNSAFE
spiffe://example.org/github/myorg/myrepo
```

A push to `main` and a PR from an external contributor both produce
`spiffe://example.org/github/myorg/myrepo`. The contributor's workflow gets the same SVID as
the production deploy.

**Anti-pattern 2: owner name only — every repository in the org is identical**

```
// UNSAFE
spiffe://example.org/github/myorg
```

Every workflow in every repository under `myorg` receives the same SVID.

**Anti-pattern 3: `actor` as workload identity**

```
// UNSAFE
spiffe://example.org/github/{{.actor}}/{{.repository_owner}}/{{.repository}}
```

Anyone who can trigger the workflow — including external contributors opening a pull request —
can obtain the SVID, regardless of which branch or workflow file runs.

**Anti-pattern 4: `workflow` display name instead of `job_workflow_ref`**

```
// FRAGILE
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}/{{.workflow}}
```

Renaming the workflow from `Deploy` to `Deploy to Production` silently changes the SVID and
breaks downstream RBAC with no cryptographic signal. `job_workflow_ref` is keyed on the file
path and is unaffected by renames.

**Anti-pattern 5: `head_ref` for pull request workflows**

```
// UNSAFE for pull_request events
spiffe://example.org/github/{{.repository_owner}}/{{.repository}}/{{.head_ref}}
```

`head_ref` is the branch name in the contributor's fork. A contributor can name their branch
`main` or `release/prod` to collide with a privileged identity.

### Loss inventory

| Dropped claim | What downstream relying parties lose |
|---|---|
| `ref` | Cannot distinguish `main` from a contributor PR branch or release branch |
| `job_workflow_ref` | Cannot distinguish `deploy.yml` from `ci.yml`; all workflows in a repo share an identity |
| `environment` | Cannot distinguish approval-gated deploys from unapproved workflow runs |
| `repository_id` | If the repo is renamed or transferred, the SVID path changes; downstream policy referencing the old name silently stops matching |
| `repository_owner_id` | If the org is renamed and the name is claimed by another party, a name-based SVID could be issued to the wrong workload |
| `sha` | No per-commit auditability in the SVID itself (still available in GitHub audit logs) |

---

## Kubernetes Service Account Token

Kubernetes projected service account tokens are issued by the API server and validated by
spire-identity-exchange via the TokenReview API. See the Kubernetes documentation on
[service account token volume projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)
for the canonical token reference.

### Claim inventory

| Claim | Description | Stability | Example value |
|---|---|---|---|
| `sub` | Composite subject. Format: `system:serviceaccount:<namespace>:<name>`. | Stable while SA exists | `system:serviceaccount:prod:payment-processor` |
| `iss` | Issuer. The Kubernetes API server URL or configured issuer. | Stable (identifies the cluster) | `https://kubernetes.default.svc` |
| `aud` | Audience. Set at token request time. | Operator-defined | `spire-identity-exchange` |
| `kubernetes.io.namespace` | Namespace of the service account. | Stable | `prod` |
| `kubernetes.io.serviceaccount.name` | Name of the service account. | Stable while SA exists | `payment-processor` |
| `kubernetes.io.serviceaccount.uid` | Immutable UID of the service account. Survives renames. | Permanent | `abc123-...` |
| `kubernetes.io.pod.name` | Name of the pod the token is bound to. Only present in pod-bound tokens. | Ephemeral (pod lifetime) | `payment-processor-abc12` |
| `kubernetes.io.pod.uid` | UID of the bound pod. Only present in pod-bound tokens. | Ephemeral | `xyz789-...` |
| `kubernetes.io.node.name` | Name of the node. Only present in node-bound tokens. | Stable while node exists | `node-1` |

> **Note on claim names:** projected service-account tokens (from `kubectl create token` and
> the TokenRequest API) nest these fields under a `kubernetes.io` object. Templates access
> them with chained `index`: `{{index . "kubernetes.io" "namespace"}}`,
> `{{index . "kubernetes.io" "serviceaccount" "name"}}`.
>
> Legacy secret-mounted service-account tokens (pre-1.21, no longer produced by default) used
> flat keys like `kubernetes.io/serviceaccount/namespace`. If you still need to support those,
> use `{{index . "kubernetes.io/serviceaccount/namespace"}}` for that token type and gate the
> deployment to one form or the other; the two formats are not interchangeable.

### Recommended claims for encoding in the SPIFFE ID

Namespace and service account name are the two load-bearing claims. They map directly to
Kubernetes' own primary workload identity model — the same discriminators used by the
[SPIRE Kubernetes workload attestor](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md)
to identify pods.

| Claim | Why it is load-bearing |
|---|---|
| `kubernetes.io.namespace` | Namespace is the primary isolation boundary in Kubernetes. Without it, a service account named `app` in any namespace gets the same SVID. |
| `kubernetes.io.serviceaccount.name` | Scopes the identity to a specific workload within the namespace. |

For high-security scenarios where a service account being deleted and recreated with the same
name must produce a different SVID, include `kubernetes.io.serviceaccount.uid` in the template.

### Claims to never use as the sole identifier

| Claim | Why |
|---|---|
| `iss` alone | Identifies the cluster, not the workload. Every service account in the cluster shares the same issuer. |
| `kubernetes.io.pod.name` | Pod names are ephemeral. A new pod for the same workload receives a different name and therefore a different SVID. Downstream relying parties cannot write durable policy against it. Use for audit context only. |
| `sub` unparsed | The composite `system:serviceaccount:<ns>:<name>` string couples downstream policy to a colon-separated format. Prefer encoding namespace and SA name as structured path segments for clarity and future resilience. |

### Canonical reference template

**Minimum safe template** — namespace and service account name (projected tokens):

```
spiffe://{{.trust_domain}}/k8s/ns/{{index . "kubernetes.io" "namespace"}}/sa/{{index . "kubernetes.io" "serviceaccount" "name"}}
```

This produces identities like:

```
spiffe://example.org/k8s/ns/prod/sa/payment-processor
```

Example configuration:

```jsonc
"k8sSAToken": {
  "enabled": true,
  "apiHost": "https://kubernetes.default.svc:443",
  "audiences": ["spire-identity-exchange"],
  "spiffeIdTemplate": "spiffe://{{.trust_domain}}/k8s/ns/{{index . \"kubernetes.io\" \"namespace\"}}/sa/{{index . \"kubernetes.io\" \"serviceaccount\" \"name\"}}"
}
```

> Templates that reference required claim keys will fail at SVID derivation time if any
> referenced claim is missing from the validated token. Tokens whose audience does not
> match the `audiences` list are rejected by the TokenReview call.

### Common anti-patterns

**Anti-pattern 1: namespace only — every SA in the namespace is identical**

```
// UNSAFE
spiffe://example.org/k8s/ns/prod
```

Every service account in `prod` — including low-privilege ones — gets the same SVID.

**Anti-pattern 2: using `sub` without parsing**

```
// FRAGILE
spiffe://example.org/k8s/{{.sub}}
// produces: spiffe://example.org/k8s/system:serviceaccount:prod:payment-processor
```

Downstream policy must match a colon-delimited string. This works but is fragile and hard to
read in RBAC rules. Use the structured template above.

**Anti-pattern 3: pod-scoped identity for a persistent service**

```
// FRAGILE for persistent workloads
spiffe://example.org/k8s/ns/prod/pod/{{index . "kubernetes.io/serviceaccount/pod.name"}}
```

When the pod is replaced (rollout, eviction, crash), the new pod gets a different SVID. Any
downstream peer that authorized the old SVID rejects the new connection until policy is updated.

### Loss inventory

| Dropped claim | What downstream relying parties lose |
|---|---|
| Namespace | Cannot scope policy to a namespace; all workloads with the same SA name across all namespaces are indistinguishable |
| Service account name | Cannot distinguish different workloads within the same namespace |
| `service-account.uid` | If a service account is deleted and recreated with the same name, the new SA silently obtains the same SVID |
| Pod name | No per-pod granularity (usually the correct trade-off for persistent services) |

# Auth plugin: Kubernetes PSAT "k8s_psat"

Validates Kubernetes projected service account tokens (PSATs) and generates SPIRE selectors identifying the caller by namespace, service account, pod, node, and cluster.

Uses a dual-stage validation pipeline:
1. **In-process JWKS signature check** (optional, enabled by default) — verifies the token's signature, issuer, audience, and expiration against the cluster's published JWKS without an API round-trip.
2. **Authoritative TokenReview** (optional, enabled by default) — round-trips to the Kubernetes API server to validate the token against the cluster's live state.

At least one validation stage must remain active.

The plugin name `k8s_psat` matches SPIRE's node-attestor naming for projected service account tokens, so operators see a single consistent identifier across both attestation and exchange surfaces.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clusterName` | string | no | Operator-defined cluster identifier. Injected into the claim map as `k8s_cluster_name`. Must come from configuration, never from the request. |
| `audiences` | string array | when `jwksCheck` enabled | Expected token audiences. Strongly recommended to configure a dedicated audience (e.g. `spire-identity-exchange`). Required when the in-process JWKS check is enabled. |
| `allowedNamespaces` | string array | see note | Kubernetes namespaces allowed. Supports trailing wildcard (`*`). At least one of `allowedNamespaces` or `allowedServiceAccounts` must be set. |
| `allowedServiceAccounts` | string array | see note | Service accounts allowed, in `namespace/serviceAccountName` format. Supports trailing wildcard (`*`). At least one required if `allowedNamespaces` is empty. |
| `kubeconfig` | string | no | Path to a kubeconfig file for API server connectivity. When running in-cluster, the pod's service account credentials are used automatically and this field is ignored. |
| `jwksCheck` | bool | no | Enable the in-process JWKS signature check. Default: `true`. Disabling removes offline signature verification. |
| `tokenReview` | bool | no | Enable the authoritative TokenReview round-trip. Default: `true`. Disabling removes live-state validation. |

When both `allowedNamespaces` and `allowedServiceAccounts` are set, the token must match **both** lists (AND logic).

## Selector reference

Selector type: `k8s_psat`

| Selector key | Value format | Condition |
|---|---|---|
| `cluster_name` | operator-defined string | when `clusterName` is configured |
| `namespace` | Kubernetes namespace | always (from `kubernetes.io.namespace` or legacy claim) |
| `service_account_name` | service account name | always |
| `service_account_uid` | K8s UID | always |
| `pod_name` | pod name | when token is pod-bound |
| `pod_uid` | pod UID | when token is pod-bound |
| `node_name` | node name | when token has node binding |
| `node_uid` | node UID | when token has node binding |
| `sub` | `system:serviceaccount:<ns>:<sa>` | always |

## Validation flow

The plugin supports two independent validation stages, both enabled by default:

1. **JWKS signature check** (in-process) — Discovers the API server's OIDC configuration, fetches and caches JWKS keys, verifies the token signature, issuer, audience, and expiration locally. This protects the API server from a flood of bogus tokens (no amplification).

2. **TokenReview** (authoritative) — Sends the token to the Kubernetes API server for live validation. Cross-checks the JWT `sub` claim against the TokenReview response principal and enforces that the principal is a service account (not a user or group). Enforces namespace and service-account allowlists.

When both stages run, JWKS runs first and TokenReview's claims are authoritative.

## Example configuration

```yaml
auth:
  plugins:
    - name: "production-cluster"
      plugin: "k8s_psat"
      config:
        clusterName: "prod-us-east"
        audiences: ["spire-identity-exchange"]
        allowedNamespaces:
          - "prod-*"
        allowedServiceAccounts:
          - "prod-*/app-sa"
        kubeconfig: "/etc/sie/kubeconfig"
```

## Security considerations

- The `clusterName` field must come from operator configuration, never from the token — accepting a caller-supplied cluster name would allow cross-cluster identity impersonation.
- Use `service_account_uid` in registration entries for immutable SA identity. Service account names can be reused if the SA is deleted and recreated.
- `pod_name` is ephemeral — pods are replaced during rollouts, evictions, and crashes. Use `service_account_name` or `service_account_uid` for durable workload identity.
- Node information in projected SA tokens (`node_name`, `node_uid`) is **not verified** by the Kubernetes API server during authentication. Do not use node claims as security-critical identity anchors without additional verification.
- When `jwksCheck` is disabled, every token validation requires a live API call. When `tokenReview` is disabled, token revocation and service account deletion are not reflected. Ensure at least one stage is always enabled.

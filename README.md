# spire-identity-exchange

A SPIRE integration service that bridges non-SPIFFE workload identity to the [SPIRE](https://spiffe.io/docs/latest/spire-about/) ecosystem — enabling platform-native tokens (GitHub Actions OIDC, GitLab CI/CD OIDC, Kubernetes service account tokens, and SPIFFE SVIDs from other trust domains) to be exchanged for SPIRE-issued SVIDs via the SPIRE Agent's Delegated Identity API.

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/spire-identity-exchange)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spire/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spire/blob/main/MATURITY.md#development)

## Warning

This code is in an early and experimental stage of development. Please do not use it in production yet. Please consider testing it out, providing feedback,
and possibly submitting fixes.

## Background

Workloads in CI/CD pipelines, Kubernetes clusters, and other platforms already possess platform-native identity tokens (OIDC tokens, service account tokens). The SPIRE agent model typically requires a SPIRE agent on every host, plus workload registration entries keyed by process-level selectors.

spire-identity-exchange bridges these worlds: it accepts platform-native tokens from workloads, validates them using pluggable authentication plugins, generates SPIRE selectors from the validated claims, and calls the SPIRE Agent's Delegated Identity API to mint SVIDs. The SPIRE Agent handles SVID issuance against its existing registration entries — no dynamic registration, no agent per workload host.

Key differences from the agent-per-host model:

- Workloads authenticate with tokens they already possess — no SPIRE agent binary, socket, or join token required.
- SVID issuance is governed by SPIRE registration entries matching the generated selectors, not by server-side SPIFFE ID templates.
- Selectors carry rich claim data (repository, workflow, namespace, SA, trust domain, etc.) enabling fine-grained authorization in SPIRE registration entries.

More details can be found in our talk at **KubeCon + SecurityCon 2025**:
[From Adoption to Innovation: LinkedIn's SPIRE Journey](https://static.sched.com/hosted_files/colocatedeventsna2025/eb/From%20Adoption%20to%20Innovation%20LinkedIn%E2%80%99s%20SPIRE%20Journey.pdf)

## Architecture

```
                        ┌──── Identity Providers (pluggable) ────┐
                        │  GitHub Actions  │  GitLab CI/CD       │
                        │  K8s PSAT        │  SPIFFE SVID JWT    │
                        └────────────────────┬───────────────────┘
                                             │ token (+ optional CSR)
                                             │
                                             ▼
                     ┌──────────────────────────────────────────┐
                     │          spire-identity-exchange         │
                     │                                          │
                     │   1. check replay cache                  │
                     │   2. validate token via plugin           │
                     │   3. generate SPIRE selectors from claims│
                     │   4. call Delegated Identity API         │
                     └────────────────────┬─────────────────────┘
                                          │ selectors
                                          │ (Unix socket)
                                          ▼
                              ┌──────────────────────────┐
                              │       SPIRE Agent         │
                              │  Delegated Identity API   │
                              │                           │
                              │  match selectors against  │
                              │  registration entries →   │
                              │  mint SVID                │
                              └────────────┬──────────────┘
                                           │ SVID
                                           ▼
                     ┌──────────────────────────────────────────┐
                     │          spire-identity-exchange         │
                     │            (return to workload)          │
                     └──────────────────────────────────────────┘
                                           │
                                           ▼
                                    Workload (X.509 or JWT SVID)
```

spire-identity-exchange connects to the SPIRE Agent over a Unix domain socket using the Delegated Identity API. The agent matches the generated selectors against its registration entries and returns the SVID. No direct communication with the SPIRE Server is needed — the agent handles all SVID issuance.

For multi-instance deployments, the replay cache should be backed by a shared central store (e.g. Redis) so that a token cannot be replayed against a different instance.

## Deployment Modes

spire-identity-exchange supports one primary deployment topology that connects to the SPIRE Agent's Delegated Identity API.

A legacy deployment mode (co-located with SPIRE Server, using SPIFFE ID templates) is available via the `-tags legacy` build flag — see the [Legacy mode](#legacy-mode) section for details.

### Standard Mode: With SPIRE Agent

spire-identity-exchange runs on a host (physical, VM, or container) that also runs a SPIRE Agent. It connects to the SPIRE Agent over a Unix domain socket using the Delegated Identity API.

1. A SPIRE agent runs on the same host as spire-identity-exchange (or is reachable via a mounted Unix socket).
2. The SPIRE agent has registration entries with selectors matching the claims that spire-identity-exchange's plugins generate.
3. A workload sends its platform-native token to spire-identity-exchange.
4. spire-identity-exchange validates the token, generates SPIRE selectors from the claims, and calls the SPIRE Agent's Delegated Identity API.
5. The agent matches the selectors against its registration entries and mints an SVID.

The SPIRE agent handles all SVID issuance — spire-identity-exchange never contacts the SPIRE Server directly. This means:
- SPIFFE IDs are determined by SPIRE registration entries, not by spire-identity-exchange configuration.
- SVID revocation and rotation follow the agent's standard lifecycle.
- spire-identity-exchange's privilege is scoped by the agent's `authorized_delegates` configuration.

### Legacy Mode: Co-located with SPIRE Server

> Available with the `-tags legacy` build flag.

SPIRE server co-location mode is the original deployment model, now maintained as a legacy path. spire-identity-exchange runs on the same host as the SPIRE server and connects via Unix domain socket, using SPIFFE ID templates to derive workload identities from token claims. See the build section for compilation instructions.

## Supported Authentication Methods

spire-identity-exchange supports pluggable authentication via a dynamic plugin system. Each plugin validates a specific token type and generates SPIRE selectors. The following plugins are built in:

| Plugin | Token type | Selector type | Configuration reference |
|---|---|---|---|
| **GitHub Actions OIDC** (`github`) | GitHub Actions OIDC JWTs via JWKS | `github_actions` | [plugin_github.md](docs/plugin_github.md) |
| **GitLab CI/CD OIDC** (`gitlab`) | GitLab CI/CD OIDC JWTs via JWKS | `gitlab_ci` | [plugin_gitlab.md](docs/plugin_gitlab.md) |
| **Kubernetes PSAT** (`k8s_psat`) | K8s projected SA tokens via JWKS + TokenReview | `k8s_psat` | [plugin_k8s_psat.md](docs/plugin_k8s_psat.md) |
| **SPIFFE SVID JWT** (`spiffe`) | Incoming SPIFFE SVID JWTs via JWKS | `spiffe` | [plugin_spiffe.md](docs/plugin_spiffe.md) |

Additional authentication methods can be added by implementing the `validator.TokenValidatorLoaderGenerator` interface (see [pkg/validator/](pkg/validator/)).

## Prerequisites

- A running [SPIRE Agent](https://spiffe.io/docs/latest/deploying/install-agent/) with the Delegated Identity API enabled (`authorized_delegates` configured)
- A running [SPIRE Server](https://spiffe.io/docs/latest/deploying/install-server/) that the agent connects to
- SPIRE registration entries with selectors matching the token claims
- Go 1.24+

## Building

The default build produces the agent-based binary:

```bash
make build
# binaries under build/<os>/<arch>/ (e.g. build/linux/amd64/spire-identity-exchange-server)
```

For the legacy server-based workflow (SPIFFE ID templates, direct SPIRE Server API):

```bash
make build spire_identity_exchange_server_TAGS=legacy
```

## Configuration

spire-identity-exchange is configured via a JSON or YAML file passed with `--config`.

```bash
export SPIFFE_TRUST_DOMAIN=example.org
source config/defualt.env
build/linux/amd64/spire-identity-exchange --config config/default.conf -expand-env
```

### Plugin-based configuration (default)

Authentication methods are configured via the `auth.plugins` array. Each entry specifies a user-defined name, a plugin type, and plugin-specific configuration.

```jsonc
{
  "name": "spire-identity-exchange",
  "logLevel": "info",

  "server": {
    "grpcPort": 8443,       // gRPC server port
    "metricsPort": 9090,    // Prometheus metrics port
    "restPort": 8444,       // Optional HTTP REST port (see REST API below)
    "tls": {
      "certFile": "certs/server.crt",
      "keyFile":  "certs/server.key"
    }
  },

  "spire": {
    "agentDelegatedSocketPath": "/tmp/spire-agent/admin/api.sock",
    "agentWorkloadSocketPath": "/tmp/spire-agent/public/api.sock",
    "trustDomain": "example.org",
    "svidTTL": "5m"
  },

  "auth": {
    "plugins": [
      {
        "name": "github-actions",
        "plugin": "github",
        "config": {
          "issuerURL": "https://token.actions.githubusercontent.com",
          "audiences": ["spire-identity-exchange"],
          "allowedRepositoryOwners": ["my-org"]
        }
      },
      {
        "name": "kubernetes-prod",
        "plugin": "k8s_psat",
        "config": {
          "clusterName": "prod-us-east",
          "audiences": ["spire-identity-exchange"],
          "allowedNamespaces": ["prod-*"],
          "allowedServiceAccounts": ["prod-*/app"]
        }
      }
    ]
  }
}
```

At least one plugin must be configured in `auth.plugins`.

### Purpose mode

The `purposeMode` setting controls replay cache scoping:

- `"shared"` (default) — a token can be used exactly once for any SVID type.
- `"purpose"` — a token can be used once per SVID type (one X.509 + one JWT per token).

### Legacy configuration

The legacy build (`-tags legacy`) uses top-level `githubOIDC` and `k8sSAToken` configuration blocks instead of `auth.plugins`. See the [Legacy mode](#legacy-mode) section.

### Selectors vs. SPIFFE ID templates

In the default (agent-based) mode, spire-identity-exchange does **not** derive SPIFFE IDs from token claims. Instead, each plugin generates **SPIRE selectors** from the validated claims, and SVID issuance is driven by SPIRE registration entries that match those selectors. This means SPIFFE IDs are entirely managed in SPIRE registration entries — no Go templates required.

The legacy mode (`-tags legacy`) uses SPIFFE ID templates to derive workload identities. For a full security reference on template-based SPIFFE ID derivation, see [docs/spiffe-id-template-guide.md](docs/spiffe-id-template-guide.md) and [docs/spiffe-id-token-reference.md](docs/spiffe-id-token-reference.md).

## Local testing

### End-to-end testing

An automated end-to-end test script is available at [scripts/e2e-local.sh](scripts/e2e-local.sh). It starts a SPIRE server and agent, configures the exchange, runs a mock GitHub OIDC server, and exercises the gRPC MintCertificate flow end-to-end.

**Prerequisites:** [SPIRE](https://spiffe.io/docs/latest/deploying/install-server/) (server + agent) running locally with the Delegated Identity API enabled, [grpcurl](https://github.com/fullstorydev/grpcurl).

**1. Generate TLS certs for the gRPC/HTTP server (one-time):**
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/server.key -out certs/server.crt \
  -sha256 -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

**2. Start the mock OIDC server** (in a separate terminal):
```bash
go run ./examples/mock-github-oidc --audience spire-identity-exchange
```

**3. Start spire-identity-exchange** (in a separate terminal):
```bash
make build
build/bin/spire-identity-exchange --config config/legacy/config.example-local.json
```

**4. Mint a certificate via the PluginAuth gRPC API:**
```bash
export GITHUB_TOKEN="<token from mock server output>"

grpcurl -insecure \
  -d '{
    "pluginAuthList": {
      "plugins": [
        {
          "pluginName": "github-actions",
          "token": "'"${GITHUB_TOKEN}"'"
        }
      ]
    },
    "serverKeyGenRequest": {}
  }' \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate
```

**5. Mint a certificate via the REST API:**
```bash
export GITHUB_TOKEN="<token from mock server output>"

curl -k -X POST https://localhost:8444/api/v1/svid/github-actions/x509 \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Content-Type: application/json"
```

### Inspecting the service

```bash
# List gRPC services
grpcurl -insecure localhost:8443 list

# Describe the API
grpcurl -insecure localhost:8443 describe proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi

# Fetch the trust bundle via REST
curl -k https://localhost:8444/api/v1/trustbundle/x509
```

## Metrics

spire-identity-exchange exposes Prometheus metrics on `metricsPort` (default `9090`):

```bash
curl http://localhost:9090/metrics
```

Key metrics:

| Metric | Description |
|---|---|
| `pki_spire_identity_exchange_operation_duration_seconds` | Latency histogram per operation (`validate_token`, `fetch_jwks`, `mint_certificate_by_plugin`, `mint_certificate_by_github_oidc`, `mint_certificate_by_k8s_sa`). Labels: `component`, `plugin`, `operation`, `status`. |
| `pki_spire_identity_exchange_operation_count_total` | Request count, same labels and operations as above. |

Standard Go runtime and process metrics are also exported with the `pki_spire_identity_exchange_` prefix (e.g. `pki_spire_identity_exchange_go_goroutines`, `pki_spire_identity_exchange_process_cpu_seconds_total`).

## Project structure

```
api/                            # Protobuf definitions and generated Go code
cmd/
  spire-identity-exchange-server/  # Main server binary (entry point + wiring)
  spire-credentialcomposer-identity-exchange/  # SPIRE CredentialComposer plugin
  spire-server-attestor-spiffe-workload-api/   # Trust bundle HTTP server
docs/                           # Documentation (plugin reference, SPIFFE ID guides)
config/                         # Example configuration files
pkg/
  validator/                    # Plugin system
    interface.go                # Core interfaces (TokenValidator, SelectorGenerator)
    purpose.go                  # Purpose / PurposeResolver for replay cache
    claims.go / jwtclaims.go    # Claim types
    allowlist.go                # Wildcard suffix matching
    registry/
      registry.go               # AllBuiltinPlugins map
    jwt/                        # Generic JWT validator + key provider (base for github, gitlab, spiffe)
    github/                     # GitHub Actions OIDC plugin
    gitlab/                     # GitLab CI/CD OIDC plugin
    k8s/                        # Kubernetes PSAT plugin
    spiffe/                     # SPIFFE SVID JWT plugin
internal/
  config/                       # Configuration structs and validation
  const/                        # Shared constants (claim names, metric labels)
  cache/                        # Replay detection (ReplayCache, ReplayCheckingValidator)
  github-oidc/                  # Legacy GitHub Actions OIDC validator
  k8s-sa-token/                 # Legacy Kubernetes SA token validator
  metrics/                      # Metrics interface and Prometheus implementation
  service/                      # gRPC server, request dispatch, certificate minting
  spireagent/delegated/         # Delegated Identity API client
  utils/                        # JWT claim helpers, certificate utilities
k8s/                            # Kubernetes manifests
examples/                       # Example servers (mock OIDC)
scripts/                        # Automation (e2e-local.sh)
```

## Contributing

Contributions are welcome. Please open an issue or pull request. When adding a new authentication method:

1. Implement `validator.TokenValidatorLoaderGenerator` in a new `pkg/validator/<method>/` package (see existing plugins for reference)
2. Register it in `pkg/validator/registry/registry.go`

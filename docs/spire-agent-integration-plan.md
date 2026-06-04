# SPIRE Agent Integration Plan

This document describes how to extend `spire-identity-exchange` to talk to a SPIRE Agent instead of (or in addition to) the SPIRE Server directly. There are two independent pieces:

- **Piece A** — Use the Workload API for the exchange's own SVID (server-side TLS on the public listener).
- **Piece B** — Use the Delegated Identity API for minting/fetching SVIDs returned to callers.

Today the exchange:

- Loads the listener TLS cert from disk (`server.tls.certFile` / `keyFile`), which never rotates — see [internal/service/runner.go](../internal/service/runner.go).
- Calls SPIRE Server's SVID v1 API (`MintX509SVID` / `MintJWTSVID`) over a private UDS — see [internal/service/mintcertificate.go](../internal/service/mintcertificate.go).

The target deployment (per the architecture diagram) inserts SPIRE Agent(s) between the exchange and the SPIRE Server. See [project_six_agent_topology.md](https://github.com/spiffe/spire-identity-exchange) for the node-alias HA topology behind the two-agent split.

---

## Piece A — Workload API for the exchange's own SVID

**Goal:** Replace the static, disk-loaded TLS cert with a SPIFFE Workload API source so the listener SVID rotates automatically and follows whatever the Main agent's attestation produces.

### What changes

| Area | Before | After |
|---|---|---|
| Listener cert | `tls.LoadX509KeyPair(certFile, keyFile)` | `tlsconfig.TLSServerConfig(x509Source)` |
| Rotation | Manual (operator replaces files, restart) | Automatic (agent rotates via workload API) |
| Config | `server.tls.{certFile,keyFile}` | `spireAgent.workloadAPISocketPath` |
| Dependency | `crypto/tls` only | `github.com/spiffe/go-spiffe/v2/{workloadapi,spiffetls/tlsconfig}` |

### Config additions

```json
"spireAgent": {
  "workloadAPISocketPath": "/var/run/spire/agents/main/public/api.sock"
}
```

Add validation that the socket path is set and is an absolute path. The legacy `server.tls.{certFile,keyFile}` block can either be deleted or kept as a dev-only fallback gated by a `mode` flag — recommendation is to **delete** it; the exchange is a SPIFFE workload, so a static disk cert is the wrong shape long-term.

### Code changes (concrete)

1. **[internal/config/config.go](../internal/config/config.go)** — add a `SpireAgentConfig` struct and a `SpireAgent SpireAgentConfig` field on `SpireIdentityExchangeConfig`. Validate `workloadAPISocketPath` is non-empty and absolute. Remove or weaken `TLSConfig` validation.

2. **[internal/service/runner.go](../internal/service/runner.go)** — replace the `tls.LoadX509KeyPair` block (around lines 97-104) with:

   ```go
   src, err := workloadapi.NewX509Source(ctx,
       workloadapi.WithClientOptions(
           workloadapi.WithAddr("unix://"+cfg.SpireAgent.WorkloadAPISocketPath),
       ),
   )
   if err != nil {
       return fmt.Errorf("failed to create X509 source from workload API: %w", err)
   }
   defer src.Close()

   tlsConfig := tlsconfig.TLSServerConfig(src)
   tlsConfig.MinVersion = tls.VersionTLS13
   ```

   Both the gRPC server and the HTTP gateway already share `tlsConfig` — no other listener changes needed.

3. **Imports** — `github.com/spiffe/go-spiffe/v2/workloadapi`, `github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig`. Both are already transitively in `go.sum` via `spire-api-sdk`.

4. **Operator docs / example config** — update [config/config.example.json](../config/config.example.json) and [config/config.example-local.json](../config/config.example-local.json).

### Operator prerequisites

- A registration entry must exist on SPIRE Server giving the exchange process its own SPIFFE ID (e.g. `spiffe://<td>/spire-identity-exchange/server`), parented to whichever agent serves the process (Main agent in the two-agent topology), with selectors matching the running process (`unix:uid:…`, `unix:path:…`).
- The Main agent's public socket must be reachable from the exchange process (same node, filesystem perms).

### Risk / rollback

- **Risk:** misconfigured agent socket → process can't start (no listener cert). Surfaces immediately at startup, not in production traffic. Acceptable.
- **Rollback:** revert config change. No data migration. The disk-cert code path can be retained behind a config flag during a rollout window if desired, but it adds dead-code-removal debt — prefer a clean swap on a maintenance window.

### Effort

~50–100 lines including config, validation, tests. One PR.

---

## Piece B — Delegated Identity API for minted SVIDs

**Goal:** Replace direct SPIRE Server `MintX509SVID` / `MintJWTSVID` calls with the SPIRE Agent's Delegated Identity API on the SIX agent's admin socket.

### Critical semantic difference (read before designing)

The Delegated Identity API is **not** a "mint with arbitrary SPIFFE ID and CSR" API. The four RPCs (verified against [spire/pkg/agent/api/delegatedidentity/v1/service.go](../../spire/pkg/agent/api/delegatedidentity/v1/service.go)) are:

| RPC | Input | Returns |
|---|---|---|
| `SubscribeToX509SVIDs` | `selectors` | Stream of SVIDs for registration entries matching the selectors |
| `SubscribeToX509Bundles` | — | Stream of trust bundles |
| `FetchJWTSVIDs` | `audiences`, `selectors` | JWT-SVIDs for matching entries |
| `SubscribeToJWTBundles` | — | Stream of JWT signing keys |

The agent serves SVIDs **for registration entries that already exist** on SPIRE Server (delivered to the agent via the normal entry-distribution path). The CSR and arbitrary-SPIFFE-ID model from `MintX509SVID` is gone.

This collides with how the exchange works today:

| Today (Server SVID v1) | With Delegated Identity API |
|---|---|
| SPIFFE ID derived from claims at request time via Go template | SPIFFE ID is whatever the matched registration entry says |
| No registration entry required | Entry **must** exist on SPIRE Server, parented under the SIX node alias |
| Caller controls TTL per-call | Entry's TTL applies (per-call TTL not honored by the agent's delegated subscribe) |
| Caller supplies CSR; key material is client-side | Agent generates key material; no CSR |

### How this fits the SIX node-alias topology

(See [project_six_agent_topology.md](https://github.com/spiffe/spire-identity-exchange) for the topology explanation.)

- A node-alias entry `spiffe://<td>/spire-identity-exchange` is registered with `parentID = spiffe://<td>/spire/server` and selectors matching the SIX agent's node attestation.
- All exchange-issuable workload entries are registered with `parentID = spiffe://<td>/spire-identity-exchange`. Every SIX agent in the cluster receives the full entry set after attestation.
- At request time the exchange maps validated token claims → selectors → `SubscribeToX509SVIDs(selectors)`. The SIX agent finds the matching entry in its local cache and returns the SVID.

### Two sub-models — pick one

**Model 1: Operator pre-registers entries.** All `github:repo:org/repo` and `k8s:sa:ns/sa` entries are created out-of-band (Terraform / a controller / `spire-server entry create`). The exchange is purely a fetcher — no SPIRE Server access needed in the request path. Cleanest, but every new repo/SA requires an entry-management workflow outside the exchange.

**Model 2: Exchange manages entries.** On the first call for a new claim shape, the exchange creates the entry via SPIRE Server's Entry API, then fetches via Delegated. Preserves "any token → any identity" semantics, but the exchange still needs Entry API access to SPIRE Server (not just the agent sockets), and requires a creation-on-demand path with careful idempotency, rate limiting, and cleanup. The diagram's "exchange only talks to agents" becomes "exchange talks to two agents + Entry API on server."

**Recommendation:** Model 1. It matches the SIX-alias topology better, keeps the exchange stateless, and pushes the "who is allowed an identity" decision into entry management (a deliberate, auditable surface) rather than into the exchange's claims→template code.

### What disappears under Model 1

- `spiffeIdTemplate` config on GitHub OIDC and K8s SA blocks — no longer the source of truth for the SPIFFE ID.
- The CSR validation path in `mintX509SVIDFromClaims` — the agent generates the key.
- The server-side-keygen path (`mintX509SVIDServerKeyGen`) — the agent already does this.
- Per-call `Ttl` from the request — the entry's TTL applies.

That's substantial behavior loss. **The exchange's public API may need to change** (e.g. drop the CSR field, drop the per-call TTL field, or document them as ignored). This is the biggest decision in Piece B.

### What needs to be added

1. **`SVIDIssuer` interface in `internal/service`** — abstract the two backends.

   ```go
   type SVIDIssuer interface {
       IssueX509(ctx context.Context, selectors []*types.Selector) (*X509SVID, error)
       IssueJWT(ctx context.Context, selectors []*types.Selector, audiences []string) (*JWTSVID, error)
   }
   ```

   Implementations: `serverSVIDIssuer` (current behavior, kept for transition / non-SIX deployments) and `delegatedSVIDIssuer` (new).

2. **`selectorsFromClaims` per auth method** — the contract between the exchange and entry creators.

   - GitHub OIDC: `repository` claim → selector `github:repo:<repo>`. Possibly `repository_owner`, `workflow_ref`, `job_workflow_ref`, `event_name` as additional selectors so an entry can scope to a specific workflow.
   - K8s SA: `sub` claim → selector(s) like `k8s:sa:<namespace>:<sa-name>`. The selector vocabulary needs design; see the [SPIFFE ID Template Guide](spiffe-id-template-guide.md) for what claims are available.

3. **Delegated Identity client wrapper** — a small client on `delegatedidentityv1.DelegatedIdentityClient` that does a single fetch (the API is streaming, but the exchange wants one-shot semantics; take the first message from the stream then close).

4. **Config additions:**

   ```json
   "spireAgent": {
     "workloadAPISocketPath": "/var/run/spire/agents/main/public/api.sock",
     "delegatedSocketPath":   "/var/run/spire/agents/six/admin/api.sock"
   }
   ```

5. **Caller authorization on the SIX agent** — the SIX agent's `authorized_delegates` must include the exchange's own SPIFFE ID (e.g. `spiffe://<td>/spire-identity-exchange/server`). This requires an entry for the exchange process parented under the SIX alias with `unix:uid:` / `unix:path:` selectors. Document this as an operator prerequisite.

### Code changes (concrete)

- **[internal/service/mintcertificate.go](../internal/service/mintcertificate.go)** — replace direct calls at `mintcertificate.go:249`, `:293`, `:363` with `h.issuer.IssueX509(…)` / `IssueJWT(…)`. Remove/guard CSR validation in `mintX509SVIDFromClaims`. Decide fate of `mintX509SVIDServerKeyGen`.
- **`internal/service/issuer_server.go`** (new) — wraps current `spireClient.NewSVIDClient()` behavior behind `SVIDIssuer`.
- **`internal/service/issuer_delegated.go`** (new) — wraps `delegatedidentityv1.NewDelegatedIdentityClient` behind `SVIDIssuer`.
- **`internal/service/selectors.go`** (new) — `selectorsFromClaims` per auth method.
- **[internal/service/server.go](../internal/service/server.go)** — `NewGRPCHandler` takes a `SVIDIssuer` instead of a `server_util.ServerClient`; the choice is made in `main.go` based on config.
- **[cmd/spire-identity-exchange-server/main.go](../cmd/spire-identity-exchange-server/main.go)** — pick the issuer based on whether `spireAgent.delegatedSocketPath` is set.

### Operator prerequisites

- The node-alias entry `spiffe://<td>/spire-identity-exchange` must exist.
- The SIX agent must be configured with `admin_socket_path` and `authorized_delegates = ["spiffe://<td>/spire-identity-exchange/server"]`.
- Every identity the exchange is expected to issue must have a registration entry parented under the SIX alias, with selectors matching `selectorsFromClaims`'s output for that auth method.

### Effort

Several PRs. The interface swap and one issuer impl is ~200 lines plus tests. The selectors design and the public-API decision (CSR/TTL fields) are the gating discussions, not the code.

---

## Recommended sequencing

1. **Piece A first.** Independent, low-risk, immediate win (rotated listener SVID), and forces the operator-side prerequisite of running an agent next to the exchange — which Piece B builds on.
2. **Decide Piece B sub-model.** Model 1 (operator-pre-registers) recommended. Document the selectors contract per auth method.
3. **Piece B in two PRs:** (a) introduce the `SVIDIssuer` interface and refactor the existing flow behind it (no behavior change), (b) add the delegated implementation and config wiring.
4. **Public API decision.** Decide CSR field / per-call TTL field fate. Communicate to existing callers before flipping the issuer.

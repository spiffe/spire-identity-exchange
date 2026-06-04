# Delegated Identity API — Implementation Plan

This document plans the work to add SPIRE Agent **Delegated Identity API** support to `spire-identity-exchange`, picking up from where [PR #24](https://github.com/spiffe/spire-identity-exchange/pull/24) ("Initial rest api work") leaves off. It is the follow-on to [spire-agent-integration-plan.md](spire-agent-integration-plan.md) (Piece A / Piece B), now grounded in the concrete code path the PR introduces.

## Where things stand

After PR #20 (test framework) and PR #24 (REST scaffolding):

- A SIX agent topology exists in the integration test (Main + SIX, node-aliased to `spiffe://<td>/spire-identity-exchange`).
- The REST surface exists on `restPort` (8444 in test): `GET /api/v1/trustbundle/x509` works; `POST /api/v1/svid/{plugin}/x509` is a stub that returns `"Hello: <plugin> <selectors-json>"`.
- The exchange opens a Workload API stream to **Main's** public socket to keep the trust bundle warm in process memory (`trustBundleCache` + `OnX509ContextUpdate`).
- The gRPC `MintCertificate` path still calls **SPIRE Server's** `MintX509SVID` / `MintJWTSVID` directly — the broker model.
- **The delegated path is not wired:** the exchange does not yet open a connection to SIX's admin socket, the relevant manifests have bugs that keep entries from reaching SIX's cache, and the REST handler does not issue real SVIDs.

The work below plans five phases (plus a Phase 0 decision-locking step) that take the codebase from "delegated path is exploratory" to "delegated path works end-to-end in CI."

---

## How it works end-to-end (target state)

Once all phases land, a `POST /api/v1/svid/github/x509` call flows through the system like this:

```
   ┌──────────┐                ┌──────────────────┐         ┌────────────┐         ┌──────────────┐
   │  caller  │                │  exchange (REST) │         │ SIX agent  │         │ SPIRE Server │
   │ (GH job) │                │     :8444        │         │ admin UDS  │         │  (cluster)   │
   └────┬─────┘                └────────┬─────────┘         └──────┬─────┘         └──────┬───────┘
        │                               │                          │                      │
        │  ① POST /api/v1/svid/         │                          │                      │
        │    github/x509                │                          │                      │
        │    Authorization: Bearer JWT  │                          │                      │
        │──────────────────────────────▶│                          │                      │
        │                               │                          │                      │
        │            ② validate JWT (issuer=GitHub,                │                      │
        │               audience=spire-identity-exchange,          │                      │
        │               replay-cache, JWKS-cache)                  │                      │
        │                               │                          │                      │
        │            ③ pkg/validator/github/selectors.go:           │                      │
        │               claims → []selector e.g.                   │                      │
        │               github_actions:workflow_ref:repo:foo/bar   │                      │
        │                               │                          │                      │
        │                               │  ④ SubscribeToX509SVIDs( │                      │
        │                               │     selectors=[…])       │                      │
        │                               │  over UDS, no TLS        │                      │
        │                               │─────────────────────────▶│                      │
        │                               │                          │                      │
        │                               │                ⑤ peercred → PID                │
        │                               │                   workload-attest (systemd)    │
        │                               │                   → caller SPIFFE ID            │
        │                               │                   ✓ in authorized_delegates    │
        │                               │                          │                      │
        │                               │                ⑥ scan SIX's local cache        │
        │                               │                   (pre-populated via alias      │
        │                               │                    inheritance from Server)    │
        │                               │                   find entry whose selectors    │
        │                               │                   ⊆ requested                  │
        │                               │                          │                      │
        │                               │                          │   (no Server call    │
        │                               │                          │    in hot path)      │
        │                               │                          │                      │
        │                               │  ⑦ stream resp:          │                      │
        │                               │     X509SVID {           │                      │
        │                               │       CertChain, Key,    │                      │
        │                               │       Bundle, ExpiresAt} │                      │
        │                               │◀─────────────────────────│                      │
        │                               │                          │                      │
        │                               │  ⑧ encode to JSON        │                      │
        │                               │     {spiffeId, cert,     │                      │
        │                               │      key, bundle,        │                      │
        │                               │      expiresAt}          │                      │
        │                               │                          │                      │
        │  ⑨ 200 OK + JSON              │                          │                      │
        │◀──────────────────────────────│                          │                      │
        │                               │                          │                      │
```

### Step-by-step

1. **Caller hits REST** with the GitHub OIDC JWT in `Authorization: Bearer …`.
2. **Token validated** using the validator built at startup — JWKS cached, replay cache enforced, audience/issuer checked.
3. **Claims → selectors** via the existing `pkg/validator/<plugin>/selectors.go` (`GenerateSelectors`).
4. **Delegated call to SIX**: open gRPC over UDS, call `SubscribeToX509SVIDs(selectors)`. No TLS, no client cert — UDS + filesystem perms are the security boundary.
5. **SIX attests the caller** via kernel peercred + workload attestor → resolves the exchange's SPIFFE ID → checks `authorized_delegates`.
6. **SIX scans its local cache** (populated via node-alias inheritance during attestation) for an entry whose selectors are a subset of the requested set.
7. **SVID returned over the stream**: first message contains cert chain, private key, trust bundle, expiry. Exchange takes it and closes the stream.
8. **JSON encode** the SVID into the REST response shape.
9. **200 OK** with `{spiffeId, cert, key, bundle, expiresAt}`.

### What is "delegated" here

Two trust transfers happen:

- **Caller → exchange**: by JWT (GitHub OIDC, validated).
- **Exchange → SIX**: by process identity (UDS peercred + SIX's local attestation + `authorized_delegates` allow-list).

SIX doesn't need to know what kind of token the caller presented or what validation the exchange did. It trusts the exchange because the exchange's SPIFFE ID is on its allow-list, and serves whatever entry matches within its alias-rooted cache. The hot path is entirely local — no SPIRE Server call, no GitHub JWKS fetch (the JWKS is cached). The Server only participates ahead of time, populating SIX's cache via entry distribution after attestation. That's what makes this design fast and HA-friendly.

### Minimum implementation surface

| Step | Status | New code? |
|---|---|---|
| 1 | Route already exists in [PR #24](https://github.com/spiffe/spire-identity-exchange/pull/24) | No |
| 2 | Validators already built in [main.go:104-140](../cmd/spire-identity-exchange-server/main.go#L104-L140) — needs to be *reused* by the REST handler instead of constructed per request | No (reuse) |
| 3 | `pkg/validator/github/selectors.go` already in tree | No |
| **4** | **Delegated client wrapper — new** | **Yes** (~100 lines in `internal/spireagent/delegated/client.go`) |
| 5, 6 | Runs entirely inside the SIX agent process | No |
| **7** | **Stream-read + parse — new** (same file as step 4) | **Yes** (~30 lines) |
| **8** | **Replace the stub `Write("Hello: ...")` with real JSON encoding** in `handleGetX509SVID` | **Yes** (~40 lines, also fixes the WriteHeader/per-request-validator/Content-Type bugs from PR #24) |
| 9 | Falls out of step 8 | No |

Plus the surrounding plumbing: new `spire.agentDelegatedSocketPath` config field (~10 lines), main.go wiring to construct the client (~10 lines), and the **Phase 1 manifest fixes** (YAML only, ~5 line changes across 3 files).

So the Go code is roughly **150–200 lines new** + the manifest fixes. The `SVIDIssuer` interface (Phase 3 below) is a nice abstraction for keeping the broker and delegated paths separable but is **optional** if the goal is "make the REST endpoint work" without refactoring the existing gRPC path.

---

## Phase 0 — Lock in design decisions (before any code)

These choices affect the abstraction shape, so resolve them first and record the answers in the PR descriptions.

| Decision | Options | Status |
|---|---|---|
| CSR support on the delegated path | (a) Drop CSR — agent generates the key. (b) Accept caller CSR | **CONFIRMED — drop.** kfox1111 stated "For now, no csr" on PR #24. The Delegated Identity API does not take a CSR; the agent generates the key. If client-CSR is required, it stays on the broker path (and is removed when the broker path is retired). |
| REST response shape for issued SVID | (a) PEM bundle (chain + key concatenated). (b) JSON `{ "cert": "pem…", "key": "pem…", "bundle": "pem…", "spiffeId": "…", "expiresAt": … }` | **Recommended: JSON.** Easier to extend with TTL metadata and lifecycle hints. PEM-only on `/trustbundle/x509` stays as is — single thing to return. Implied by the no-CSR decision: the response body must carry the key. |
| Per-call TTL | (a) Honor a `ttl` field on the request. (b) Use entry TTL only | **Recommended: entry TTL only.** Delegated subscribe doesn't take a per-call TTL; the entry's TTL applies. Document this clearly so operators know to set TTL on the registration entries, not in client requests. |
| JWT alongside X509 | (a) Same endpoint with content negotiation. (b) Separate endpoint | **Recommended: separate endpoint.** `POST /api/v1/svid/{plugin}/jwt` mirroring `/x509`. Audience comes from request body. Avoids overloading one path with two response shapes. |
| Validator reuse | (a) Per-request construct (PR #24 stub does this). (b) Reuse the `main.go`-built validator | **Recommended: reuse.** Pass the configured validators (with replay cache + JWKS cache) into the REST handlers. The per-request construction in PR #24's stub must go before more code piles on top. Also called out by kfox1111. |
| Selectors-from-claims surface | Currently `validator.GenerateSelectors(claims)` is github-specific. | **Recommended: promote `GenerateSelectors` to the `TokenValidator` interface** so the same handler code works for K8s SA and any future plugin. |
| Broker path future | Keep indefinitely / deprecate / remove | **Pick a timeline.** Coexistence is fine short-term; long-term, the differing TTL/CSR semantics will confuse operators. |

Items still marked "Recommended" need a quick confirm from the PR author before starting Phase 1; the CSR decision is already locked.

---

## Phase 1 — Fix the manifests so SIX is functional (BLOCKER)

Without these fixes, none of the later phases can be tested end-to-end. The bugs are described in detail in the PR reviews; the summary:

### Files to fix

- **`tests/integration/github/manifests/node1-six-nodealias.yaml`**

  ```yaml
  spec:
    parentID: spiffe://${SPIFFE_TRUST_DOMAIN}/spire/server   # was /spire
    spiffeID: spiffe://${SPIFFE_TRUST_DOMAIN}/spire-identity-exchange
    selectors:
      - spiffe_id:spiffe://${SPIFFE_TRUST_DOMAIN}/spire/agent/x509pop/spire-identity-exchange/node1
  ```

  Reason: SPIRE only classifies an entry as a node alias when `ParentId.Path == "/spire/server"` (see [spire/pkg/server/cache/entrycache/fullcache.go:125](../../spire/pkg/server/cache/entrycache/fullcache.go#L125)). With `/spire`, the entry is silently inert and the alias never functions.

- **`tests/integration/github/manifests/six-spire-identity-exchange.yaml`** (introduced in PR #24)

  ```yaml
  metadata:
    name: six-spire-identity-exchange       # was node1-spire-identity-exchange (collides with another file!)
  spec:
    parentID: spiffe://${SPIFFE_TRUST_DOMAIN}/spire-identity-exchange   # was the x509pop node prefix
    spiffeID: spiffe://${SPIFFE_TRUST_DOMAIN}/spire-identity-exchange
    selectors:
      - systemd:id:spire-identity-exchange@main.service
  ```

  Two issues: the `metadata.name` collides with the existing `node1-spire-identity-exchange.yaml` (controller-manager applies last-wins, silently dropping one), and the `parentID` doesn't match either the alias or SIX's full node ID (`/node1` suffix missing).

- **`tests/integration/github/manifests/six-github-job.yaml`**

  ```yaml
  spec:
    parentID: spiffe://${SPIFFE_TRUST_DOMAIN}/spire-identity-exchange   # was the x509pop node prefix
    spiffeID: spiffe://${SPIFFE_TRUST_DOMAIN}/github/test
    selectors:
      - github_actions:workflow_ref:repo:spiffe/spire-identity-exchange
      - github_actions:workflow_ref:path:.github/workflows/test.yaml
  ```

### Test addition

Add an assertion in `tests/integration/github/run-tests.sh` that SIX has the expected entries:

```bash
# Verify SIX has alias-parented entries in its cache
sudo spire-agent api fetch -socketPath /var/run/spire/agent/sockets/six/public/api.sock 2>&1 | \
  grep -q "spiffe://example.org/spire-identity-exchange" || {
    echo "SIX is not seeing alias-parented entries — check manifests"
    exit 1
  }
```

### Scope

Pure YAML + one shell assertion. Small PR, fast review. Can land into PR #20 or standalone after #20 merges.

---

## Phase 2 — Delegated Identity client wrapper + config

### Config change

In [internal/config/config.go](../internal/config/config.go), extend `SPIREConfig`:

```go
type SPIREConfig struct {
    UnixSocketPath           string   `json:"unixSocketPath"`            // existing — server private API
    AgentWorkloadSocketPath  string   `json:"agentWorkloadSocketPath"`   // PR #24 — Main agent WLA
    AgentDelegatedSocketPath string   `json:"agentDelegatedSocketPath"`  // NEW — SIX admin socket
    TrustDomain              string   `json:"trustDomain"`
    SVIDTTL                  Duration `json:"svidTTL"`
}
```

Validation: required when the REST SVID endpoint is enabled. Suggested check (alongside the existing `RestPort` / `AgentWorkloadSocketPath` pairing):

```go
if c.Server.RestPort != 0 && c.SPIRE.AgentDelegatedSocketPath == "" {
    errs = append(errs, errors.New("spire.agentDelegatedSocketPath is required when server.restPort is enabled"))
}
```

Update `config/config.example.json` and `tests/integration/github/default.json` with realistic values:

```json
"agentDelegatedSocketPath": "/var/run/spire/agent/sockets/six/admin/api.sock"
```

### New package: `internal/spireagent/delegated/`

```go
package delegated

type Client struct {
    conn *grpc.ClientConn
    api  delegatedidentityv1.DelegatedIdentityClient
}

type X509SVID struct {
    SpiffeID   string
    CertChain  []*x509.Certificate
    PrivateKey crypto.PrivateKey
    ExpiresAt  time.Time
}

type JWTSVID struct {
    SpiffeID  string
    Token     string
    ExpiresAt time.Time
}

func NewClient(ctx context.Context, socketPath string) (*Client, error)
func (c *Client) FetchX509SVID(ctx context.Context, selectors []*types.Selector) (*X509SVID, error)
func (c *Client) FetchJWTSVID(ctx context.Context, selectors []*types.Selector, audiences []string) (*JWTSVID, error)
func (c *Client) Close() error
```

Implementation notes:

- Open the gRPC connection once at process startup using `grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))`. This is correct for UDS: security comes from filesystem permissions and SIX's peercred attestation, not TLS.
- `FetchX509SVID` calls `SubscribeToX509SVIDs`, takes the first message off the stream, then cancels the request context to close the subscription. Parse `resp.X509Svids[0]` into the local `X509SVID` struct.
- `FetchJWTSVID` is unary — straightforward call, no stream handling needed.
- Long-lived `*grpc.ClientConn`. gRPC's built-in connection management handles transient reconnects.
- Surface error categories so the REST handler can translate them: `ErrNoMatchingEntry` (no entry in SIX's cache matches the selectors), `ErrPermissionDenied` (exchange not in `authorized_delegates`), `ErrUnavailable` (SIX down / socket missing).

### Wiring in `cmd/spire-identity-exchange-server/main.go`

After the existing SPIRE Server client setup (line 75), construct the delegated client and pass it through to `service.Run`:

```go
delegatedClient, err := delegated.NewClient(ctx, cfg.SPIRE.AgentDelegatedSocketPath)
if err != nil { return err }
defer delegatedClient.Close()
```

### Scope

Standalone PR. Adds plumbing but doesn't change runtime behavior — the new client is constructed and held but nothing calls it yet. Safe to land independently.

---

## Phase 3 — Introduce `SVIDIssuer` abstraction (refactor PR, no behavior change) — OPTIONAL

> **Status: deferrable.** kfox1111's framing on PR #24 ("add the spire-agent delegated api calls to it to go from the selectors to the svid and return it") implies the delegated client can be wired directly into the REST handler without an intermediate interface. Skip this phase if the goal is to land end-to-end functionality quickly and revisit the abstraction when (or if) the broker path needs to dual-back the delegated impl. Keep it if you want the broker (gRPC) and delegated (REST) handlers to share a common dependency surface for testing.

The existing gRPC `MintCertificate` path and the new REST `POST /api/v1/svid/...` path issue SVIDs via two different backends (broker = SPIRE Server, delegated = SIX agent). An interface makes the split explicit and lets them coexist cleanly.

### New file: `internal/service/issuer.go`

```go
type SVIDIssuer interface {
    IssueX509(ctx context.Context, selectors []*types.Selector) (*delegated.X509SVID, error)
    IssueJWT(ctx context.Context, selectors []*types.Selector, audiences []string) (*delegated.JWTSVID, error)
}
```

(Or define issuer-specific result types in `internal/service` and keep `delegated.Client` types internal to the delegated package — exact placement is a style call.)

### Two implementations

- **`serverSVIDIssuer`** — wraps the existing `spireClient.NewSVIDClient()`. Used by the gRPC `MintCertificate` handler. Adapts today's calls (which take CSRs and per-call TTLs) into the selector-based interface. *Note:* server-backed issuance does not actually consume selectors — they're ignored. This is a semantic mismatch worth flagging if both paths are kept long-term.

- **`delegatedSVIDIssuer`** — wraps the Phase 2 `delegated.Client`. Used by the new REST handler.

### Refactor scope

- Add `issuer SVIDIssuer` to `SpireIdentityExchangeServer` in [internal/service/server.go](../internal/service/server.go).
- Update the gRPC `MintCertificate` handlers in [internal/service/mintcertificate.go](../internal/service/mintcertificate.go) to call `h.issuer.IssueX509(...)` / `IssueJWT(...)` instead of `h.spireClient.NewSVIDClient().MintX509SVID(...)`. For the broker path this is a behavior-preserving wrapper.
- Pass the right issuer in from `main.go` based on which path is being constructed.

### Scope

Pure refactor — gRPC tests continue to pass with `serverSVIDIssuer`. No integration test changes required. Easy review.

---

## Phase 4 — Complete the REST `POST /api/v1/svid/{plugin}/x509` handler

This is the behavior-change PR — where the delegated path actually starts issuing SVIDs end-to-end.

### 4a. Restructure: move REST handlers out of `runner.go`

`runner.go` is meant to be **server lifecycle** code (`Run`, listener setup, graceful shutdown). PR #24 dropped two REST handler bodies (`handleTrustBundleX509`, `handleGetX509SVID`) plus the `trustBundleCache` type into the same file. As the REST surface grows (X509, JWT, future endpoints), `runner.go` becomes a grab-bag.

Suggested layout:

```
internal/service/
├── runner.go              # lifecycle: Run, listeners, shutdown — stays small
├── rest/
│   ├── handlers.go        # handleGetX509SVID, handleGetJWTSVID
│   ├── trustbundle.go     # handleTrustBundleX509 + trustBundleCache
│   └── plugins.go         # plugin registry (see 4b)
```

`runner.go` reduces to: construct the dependencies (validators, issuer, trust-bundle cache, plugin registry), build the mux, mount the handlers, hand the mux to the HTTPS listener.

### 4b. Plugin registry: name → validator

The URL `POST /api/v1/svid/{plugin}/x509` has a path parameter that PR #24's stub just echoes. The real dispatch needs a registry built once at startup:

```go
// internal/service/rest/plugins.go
type PluginSet map[string]validator.TokenValidator

func (p PluginSet) Get(name string) (validator.TokenValidator, bool) {
    v, ok := p[name]
    return v, ok
}
```

Wired up in `main.go`:

```go
plugins := rest.PluginSet{}
if githubOIDCValidator != nil { plugins["github"] = githubOIDCValidator }
if k8sSATokenValidator != nil { plugins["k8s"]    = k8sSATokenValidator }
```

The handler does:

```go
v, ok := plugins.Get(r.PathValue("plugin"))
if !ok {
    http.Error(w, "unknown plugin", http.StatusBadRequest)
    return
}
claims, err := v.Validate(r.Context(), token)
// …
selectors := v.GenerateSelectors(claims)
```

Two consequences worth being explicit about:

- **Validators come from `main.go`, not the handler.** PR #24 constructs `github.NewValidator(github.Config{AllowedRepositories: ["spiffe/spire-identity-exchange"], Audiences: ["spire-identity-exchange"]})` per request with hardcoded values. That goes away — operators configure the validator once via JSON, and the handler reuses the validator that's already wrapped with the replay cache + JWKS cache.
- **`GenerateSelectors` needs to be on the `TokenValidator` interface**, not just the github concrete type, so the dispatch is plugin-agnostic. Today `pkg/validator/github` has it; promote the method to `pkg/validator/interface.go`. Each plugin implements its own selector-generation logic.

### 4c. Handler rewrite

### Handler rewrite

Replace the stub in [internal/service/runner.go](../internal/service/runner.go) with the real flow. Sketch:

```go
func handleGetX509SVID(
    issuer SVIDIssuer,
    validators map[string]validator.TokenValidator,   // keyed by plugin path-param: "github" / "k8s"
    logger *zap.Logger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        plugin := r.PathValue("plugin")
        v, ok := validators[plugin]
        if !ok {
            http.Error(w, "unknown plugin", http.StatusBadRequest)
            return
        }

        token, err := extractBearerToken(r)
        if err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }

        claims, err := v.Validate(r.Context(), token)
        if err != nil {
            logger.Info("token validation failed", zap.Error(err))
            http.Error(w, "invalid token", http.StatusUnauthorized)
            return
        }

        selectors := v.GenerateSelectors(claims)
        if len(selectors) == 0 {
            http.Error(w, "no selectors derivable from claims", http.StatusBadRequest)
            return
        }

        svid, err := issuer.IssueX509(r.Context(), selectors)
        switch {
        case errors.Is(err, delegated.ErrNoMatchingEntry):
            http.Error(w, "no registration entry matches", http.StatusNotFound)
            return
        case errors.Is(err, delegated.ErrUnavailable):
            http.Error(w, "issuance backend unavailable", http.StatusServiceUnavailable)
            return
        case err != nil:
            logger.Error("svid issuance failed", zap.Error(err))
            http.Error(w, "issuance failed", http.StatusInternalServerError)
            return
        }

        resp := struct {
            SpiffeID  string `json:"spiffeId"`
            Cert      string `json:"cert"`
            Key       string `json:"key"`
            Bundle    string `json:"bundle"`
            ExpiresAt int64  `json:"expiresAt"`
        }{
            SpiffeID:  svid.SpiffeID,
            Cert:      encodeChainPEM(svid.CertChain),
            Key:       encodePKCS8PEM(svid.PrivateKey),
            Bundle:    string(cache.Get()),
            ExpiresAt: svid.ExpiresAt.Unix(),
        }
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            logger.Error("response encode failed", zap.Error(err))
        }
    }
}
```

### Bugs from PR #24 wrapped into this PR

- **`WriteHeader(http.StatusOK)` before validation** — gone. `WriteHeader` only fires on success (implicitly via the first `Write`).
- **Per-request `github.NewValidator(...)`** — gone. Validators come from `main.go` (with replay cache, JWKS cache, configured allow-list).
- **Hardcoded `AllowedRepositories: ["spiffe/spire-identity-exchange"]`** — gone. Operator config rules.
- **`Content-Type: "plain/text"`** — moot, the new response is JSON.

### JWT counterpart

Add `POST /api/v1/svid/{plugin}/jwt` with the same shape:

```go
type jwtRequest struct {
    Audiences []string `json:"audiences"`
}
```

Validation: at least one audience is required (mirrors the gRPC `mintJWTSVIDFromClaims` check at [mintcertificate.go:274-279](../internal/service/mintcertificate.go#L274-L279)).

### Selector-generation contract

`pkg/validator/github/selectors.go` already exists. Confirm the selectors it produces (e.g., `github_actions:workflow_ref:*`) match the selectors on the alias-parented entries from Phase 1 **exactly**. A debug log in the delegated client that prints the requested selectors when `IssueX509` returns no-match is worth adding — it's the cheapest way to diagnose mismatches in operations.

Add a unit test asserting selectors are only derived after `Validate(...)` returns nil — guards against a future refactor accidentally letting unvalidated claims into selector construction.

---

## Phase 5 — Integration test

Update `tests/integration/github/run-tests.sh` to replace the stub-echo curl call with a real assertion:

```bash
RESPONSE=$(curl -fsS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -X POST https://localhost:8444/api/v1/svid/github/x509 \
  --cacert /etc/spire/identity-exchange/main/certs/server.pem)

echo "$RESPONSE" | jq -e '.spiffeId' > /dev/null || { echo "no spiffeId in response"; exit 1; }
echo "$RESPONSE" | jq -r '.cert'   > /tmp/svid.pem
echo "$RESPONSE" | jq -r '.bundle' > /tmp/bundle.pem

# Verify it's a SPIFFE cert
openssl x509 -in /tmp/svid.pem -text -noout | grep -q "URI:spiffe://" || {
  echo "issued cert has no SPIFFE URI SAN"; exit 1
}

# Verify it chains to the trust bundle
openssl verify -CAfile /tmp/bundle.pem /tmp/svid.pem || exit 1

echo "delegated X509 SVID issuance verified end-to-end"
```

Mirror the same pattern for the JWT endpoint:

```bash
RESPONSE=$(curl -fsS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -X POST https://localhost:8444/api/v1/svid/github/jwt \
  -H 'Content-Type: application/json' \
  -d '{"audiences":["foo"]}' \
  --cacert /etc/spire/identity-exchange/main/certs/server.pem)

TOKEN=$(echo "$RESPONSE" | jq -r '.token')
[ -n "$TOKEN" ] || { echo "no token in response"; exit 1; }
# (Optionally verify the JWT signature against the JWT bundle from spire-server bundle show)
```

The existing X509 `grpcurl` line (the commented-out `MintX509SVID` call from PR #20) can stay commented out, or be re-enabled if the broker path is going to be supported long-term.

---

## Phase 6 — Docs + operator guide

- **README**: add the broker-vs-delegated comparison and the recommended deployment topology (link to the existing topology section).
- **`config/config.example.json`**: include the new `agentDelegatedSocketPath` and a comment explaining what it points at.
- **`docs/spire-agent-integration-plan.md`** (the existing plan doc): update Piece B's status to "implemented" with a pointer to this document.
- **New section in this doc or a separate `docs/delegated-api-operator-guide.md`**: the operator-side prerequisites:
  - Run a SIX agent with `admin_socket_path` and `authorized_delegates` including the exchange's SPIFFE ID.
  - Pre-register entries parented under `spiffe://<td>/spire-identity-exchange` with selectors matching `pkg/validator/<plugin>/selectors.go` output.
  - Document the selector vocabulary per plugin (GitHub OIDC, K8s SA, future).

---

## Suggested PR sequence

### Minimum viable scope (matches kfox1111's PR #24 framing)

| PR | Phase(s) | Scope | Review effort |
|---|---|---|---|
| **PR-A** | Phase 1 | Manifest fixes (YAML only + one shell assertion) | Tiny |
| **PR-B** | Phase 2 | Delegated client wrapper + config field + main.go wiring | Small |
| **PR-C** | Phase 4 + 5 | Restructure handlers out of `runner.go`, plugin registry, REST handler rewrite, integration test | **Medium** — the real review attention |
| **PR-D** | Phase 6 | Docs | Tiny |

Three PRs to land the end-to-end delegated path. Phase 3 (`SVIDIssuer` abstraction) is skipped — the delegated client is wired directly into the REST handler.

### Full scope (if SVIDIssuer abstraction is wanted)

| PR | Phase(s) | Scope | Review effort |
|---|---|---|---|
| **PR-A** | Phase 1 | Manifest fixes | Tiny |
| **PR-B** | Phase 2 | Delegated client wrapper + config field + main.go wiring | Small |
| **PR-C** | Phase 3 | `SVIDIssuer` abstraction (pure refactor, no behavior change) | Small |
| **PR-D** | Phase 4 + 5 | Restructure handlers out of `runner.go`, plugin registry, REST handler rewrite, integration test | **Medium** |
| **PR-E** | Phase 6 | Docs | Tiny |

Five PRs; PR-A through PR-C are mechanically simple and review fast. PR-D is the behavior-introducing one.

### Pick which sequence

Default to the minimum-viable scope unless there's a near-term reason to dual-back the broker path (e.g., the broker path is staying long-term and needs to share testing fixtures with the delegated path). Otherwise the abstraction can be introduced later when its motivation actually materializes.

---

## Risks and gotchas

- **Connection lifecycle on the delegated client.** If SIX restarts, the gRPC `ClientConn` auto-reconnects, but the first call after the restart may fail. Decide whether to wrap with a single retry inside the client, or surface the error and rely on the caller (CI / curl client) to retry.

- **SIX agent attestation startup race.** The exchange may come up before SIX has finished attesting and populated its cache. The first delegated calls return "no matching entry." Either bake a startup wait into `run-tests.sh` (same pattern as `wait_for_jwt`), or surface 503 from the handler and document operator-side retry expectations.

- **Selector vocabulary drift.** If the validator emits selectors slightly different from what's registered on entries (e.g., `github_actions:workflow_ref:...` vs `github:workflow_ref:...`), every call returns "no match" with no obvious diagnostic. The debug-log-selectors-on-no-match note in Phase 4 is cheap defense.

- **Broker / delegated coexistence.** While both paths are wired, an operator could end up with two SVIDs for the same identity with different TTLs (broker = client-controlled, delegated = entry-controlled). Pick a deprecation timeline for the broker path before this becomes a support burden.

- **Per-call selector freshness.** The exchange must construct selectors from **validated** claims and pass them as-is. If a future refactor lets unvalidated claims sneak into selector construction, the security model breaks (the exchange could be tricked into asking for selectors that match a more-privileged entry). A unit test asserting "selectors are only derived after `Validate` returns nil" is cheap insurance.

- **`authorized_delegates` is a binary trust grant.** Once the exchange is on SIX's `authorized_delegates`, it can fetch any SVID for any entry in SIX's cache — there is no per-call authorization. The alias-parented entry tree IS the security boundary; nothing structural prevents the exchange from issuing any identity that lives under the alias. Operator discipline around what goes under the alias is essential.

- **No replay cache on the REST path today.** PR #24 constructs a fresh validator per request and skips the `cache.NewReplayCheckingValidator` wrapping that the gRPC path uses. Phase 4 fixes this by reusing the configured validator — but the fix must actually happen, or the REST path remains replay-vulnerable.

---

## Definition of done

The delegated path is "implemented" when:

1. The integration test in CI runs the full chain: real GitHub OIDC token → REST endpoint → exchange validates → derives selectors → calls SIX → SIX returns SVID → REST returns JSON with cert/key/bundle.
2. The returned cert is a valid SPIFFE-URI-SAN X.509 cert that chains to the trust bundle.
3. Replay attempts against the REST endpoint are rejected by the shared replay cache.
4. Error paths return the right status codes (401 for bad token, 404 for no matching entry, 503 for backend down, 500 for internal).
5. Docs explain to operators how to register entries under the alias and what selectors each validator emits.
6. The broker path (gRPC `MintCertificate`) continues to work — no regression — until a deprecation decision is made.

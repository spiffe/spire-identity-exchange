# Auth plugin: SPIFFE SVID JWT "spiffe"

Validates incoming SPIFFE SVID JWTs from other trust domains and generates SPIRE selectors identifying the caller by source trust domain, SPIFFE ID path, and full SPIFFE ID.

This plugin enables cross-trust-domain federation: workloads presenting a valid SPIFFE SVID JWT from a recognized trust domain can exchange it for a new SVID scoped to the local trust domain via SPIRE registration entries.

Uses the generic [JWT validator](pkg/validator/jwt/) for signature verification, key discovery, and standard claim validation. Adds SPIFFE-specific checks (trust domain match, path pattern matching) and selector generation on top.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `issuerURL` | string | **yes** | OIDC issuer URL for the SPIFFE JWT's issuing authority. Must be HTTPS. |
| `discoveryURL` | string | no | Base URL for OIDC discovery of the JWKS endpoint. Defaults to `issuerURL` when empty. |
| `audiences` | string array | **yes** | Expected JWT audience values. At least one entry required. |
| `trustDomain` | string | **yes** | Expected SPIFFE trust domain of the incoming SVID (e.g. `example.org`). Must be a valid SPIFFE trust domain. |
| `pathPatterns` | string array | **yes** | Go regular expression patterns for allowed SPIFFE ID paths. At least one pattern required. The token's `sub` claim SPIFFE ID path must match at least one pattern. |

## Selector reference

Selector type: `spiffe`

| Selector key | Value format | Condition |
|---|---|---|
| `source_trust_domain` | configured trust domain | always |
| `source_path` | SPIFFE ID path (e.g. `/workload/foo`) | when `sub` contains a valid SPIFFE ID |
| `source_spiffe_id` | full SPIFFE ID (URL-encoded) | when `sub` contains a valid SPIFFE ID |

## Validation flow

1. **JWT signature verification** — fetches the issuer's JWKS via OIDC discovery and verifies the token signature.
2. **Standard claim validation** — verifies `iss`, `aud`, and `exp` (30s clock leeway).
3. **SPIFFE ID validation** — parses the `sub` claim as a SPIFFE ID (`spiffe://<td>/<path>`), checks that the trust domain matches the configured `trustDomain`, and verifies the path matches at least one configured `pathPattern` regex.
4. **Replay detection** — the caller's replay cache prevents token reuse.

## Example configuration

```yaml
auth:
  plugins:
    - name: "peer-federation"
      plugin: "spiffe"
      config:
        issuerURL: "https://spire-server.peer.example.org"
        audiences:
          - "exchange-service"
        trustDomain: "peer.example.org"
        pathPatterns:
          - "^/workload/.*"
```

## Security considerations

- Path patterns are Go regular expressions. Test them thoroughly against expected SPIFFE ID paths to avoid accidentally allowing or rejecting valid identities.
- The `trustDomain` field establishes the trust boundary — only SPIFFE IDs from this domain are accepted. Ensure this matches the expected external trust domain exactly.
- The `issuerURL` must be the OIDC issuer of the SPIFFE JWT, which may differ from the trust domain. Use the SPIFFE bundle endpoint's OIDC discovery URL.
- Combined with a SPIRE registration entry matching `spiffe:source_trust_domain:<domain>` and `spiffe:source_path:<regex>`, this plugin enables fine-grained cross-domain federation policies.

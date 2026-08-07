Azure username: 00000000-0000-0000-0000-000000000000
Details: https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication?tabs=azure-cli

Google registry username: oauth2accesstoken

Zot username: zot
Details: https://github.com/project-zot/zot/pull/4171

## Selecting a JWT-SVID by hint

When the SPIFFE workload API returns more than one JWT-SVID for `--spiffe-audience`
(for example a SPIRE HA broker fronting several entry-scoped SVIDs), the plugin uses
the first one by default. Set `--spiffe-hint` to the operator-assigned hint on the
registration entry to pin a specific SVID instead:

```yaml
args:
  - "--spiffe-audience=spire-identity-exchange"
  - "--spiffe-hint=registry"
```

The match is exact and case sensitive. If no SVID carries the requested hint the
plugin fails with an error listing the hints that were available, rather than falling
back to a different identity.


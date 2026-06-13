// Package spiffe provides SPIRE selector generation from validated SPIFFE SVID JWT claims.
package spiffe

import (
    "fmt"

    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const SelectorType = "spiffe"

// GenerateSelectors produces SPIRE selectors from validated SPIFFE SVID JWT claims.
// Implements validator.SelectorGenerator.
//
// The generated selectors include the incoming SPIFFE identity information:
// - td:<trust-domain> for keying by the source trust domain
// - path:<path> for keying by the workload identity path
// - sub:<sub> for exact matching of the raw sub claim
//
// These selectors allow the delegated identity API to find a SPIRE registration
// entry that can mint a new SVID (potentially for a different trust domain) based
// on the validated identity of the incoming token.
func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
    raw := claims.GetRaw()
    subRaw, ok := raw["sub"]
    if !ok {
        // Should not happen if Validate() was called, but be defensive
        return nil
    }
    sub, _ := subRaw.(string)

    // Build selectors using the incoming SPIFFE identity information.
    // These selectors will be used by the delegated identity API to find
    // a SPIRE registration entry that can mint a new SVID (potentially for
    // a different trust domain).
    spiffeID, err := spiffeid.FromString(sub)
    if err != nil {
        return nil
    }
    var selectors []*types.Selector

    add := func(key, value string) {
        if value != "" {
            selectors = append(selectors, &types.Selector{
                Type:  SelectorType,
                Value: fmt.Sprintf("%s:%s", key, value),
            })
        }
    }

    // Include trust domain selector
    add("trust_domain", v.config.TrustDomain)

    // Include path selector (for matching entries by workload identity path)
    add("path", spiffeID.Path())

    // Include raw sub selector (for exact matching if needed)
    add("spiffe_id", sub)

    return selectors
}

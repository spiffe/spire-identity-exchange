// Package spiffe provides SPIRE selector generation from validated SPIFFE SVID JWT claims.
package spiffe

import (
    "fmt"
    "net/url"

    "github.com/spiffe/go-spiffe/v2/spiffeid"
    "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const SelectorType = "spiffe"

// GenerateSelectors produces SPIRE selectors from validated SPIFFE SVID JWT claims.
// Implements validator.SelectorGenerator.
//
// The generated selectors include the incoming SPIFFE identity information:
// - trust_domain:<trust-domain> for keying by the source trust domain
// - path:<path> for keying by the workload identity path
// - spiffe_id:<spiffe-id> for exact matching of the (decoded) SPIFFE ID
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
    sub, ok := subRaw.(string)
    if !ok {
        return nil
    }

    subDecoded, err := url.QueryUnescape(sub)
    if err != nil {
        return nil
    }

    // Build selectors using the incoming SPIFFE identity information.
    // These selectors will be used by the delegated identity API to find
    // a SPIRE registration entry that can mint a new SVID (potentially for
    // a different trust domain).
    spiffeID, err := spiffeid.FromString(subDecoded)
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
    add("source_trust_domain", v.config.TrustDomain)

    // Include path selector (for matching entries by workload identity path)
    add("source_path", spiffeID.Path())

    // Include raw sub selector (for exact matching if needed)
    add("source_spiffe_id", sub)

    return selectors
}

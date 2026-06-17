package stack

import (
    "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
    var selectors []*types.Selector
    stackClaims := claims.(*Claims)
    for plugin, pluginClaims := range stackClaims.PluginClaims {
        c := v.config.PluginMap[plugin].GenerateSelectors(pluginClaims)
	for _, ic := range c {
            selectors = append(selectors, ic)
	}
    }
    return selectors
}

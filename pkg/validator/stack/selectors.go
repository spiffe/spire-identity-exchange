package stack

import (
    "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
	stackClaims, ok := claims.(*Claims)
	if !ok || stackClaims == nil {
		return nil
	}

	var selectors []*types.Selector
	for plugin, pluginClaims := range stackClaims.PluginClaims {
		pluginValidator, ok := v.config.PluginMap[plugin]
		if !ok {
			return nil
		}
		selectors = append(selectors, pluginValidator.GenerateSelectors(pluginClaims)...)
	}
	return selectors
}

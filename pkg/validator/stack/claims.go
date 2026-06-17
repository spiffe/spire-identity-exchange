package stack

import (
	"math"
	"slices"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

type Claims struct {
	PluginClaims map[string]validator.Claims
	Raw          map[string]interface{}
}

func claimsFromRaw(raw map[string]interface{}) *Claims {
	return &Claims{
		Raw:          raw,
		PluginClaims: make(map[string]validator.Claims),
	}
}

func (c *Claims) GetRaw() map[string]interface{} {
	return c.Raw
}

func (c *Claims) GetUniqueID() string {
	var jti string

	keys := make([]string, 0, len(c.PluginClaims))
	for k := range c.PluginClaims {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, key := range keys {
		jti += c.PluginClaims[key].GetUniqueID()
	}
	return jti
}

func (c *Claims) GetExpiration() int64 {
	var exp int64 = math.MaxInt64
	for _, claim := range c.PluginClaims {
		pluginExp := claim.GetExpiration()
		if exp > pluginExp {
			exp = pluginExp
		}
	}
	return exp
}

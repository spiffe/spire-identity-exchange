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
		jti += key
		jti += "\x1f"
		jti += c.PluginClaims[key].GetUniqueID()
		jti += "\x1e"
	}
	return jti
}

func (c *Claims) GetExpiration() int64 {
	exp := int64(math.MaxInt64)
	for _, claim := range c.PluginClaims {
		pluginExp := claim.GetExpiration()
		if pluginExp == 0 {
			continue
		}
		if exp > pluginExp {
			exp = pluginExp
		}
	}
	if exp == int64(math.MaxInt64) {
		return 0
	}
	return exp
}

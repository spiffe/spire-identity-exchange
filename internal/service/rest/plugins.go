package rest

import (
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// Plugin pairs a token validator with a selector generator. Both are required
// for the /svid/{plugin}/x509 path to issue an SVID: Validate produces claims,
// GenerateSelectors turns those claims into SPIRE selectors.
//
// Both pkg/validator/github.Validator and (future) k8s validators implement
// both pkg/validator.TokenValidator and pkg/validator.SelectorGenerator, so a
// single concrete validator is typically stored in both fields.
type Plugin struct {
	Validator         validator.TokenValidator
	SelectorGenerator validator.SelectorGenerator
}

// PluginSet maps a URL path-param name (e.g. "github", "k8s") to its
// configured Plugin. Population happens once at startup in main.go; lookup is
// a single map read per request.
type PluginSet map[string]Plugin

// Get returns the plugin registered under name. The second return value is
// false if no plugin is registered under that name, in which case the handler
// should respond with 400.
func (p PluginSet) Get(name string) (Plugin, bool) {
	v, ok := p[name]
	return v, ok
}

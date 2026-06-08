package registry

import (
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/gitlab"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/k8s"
)

// AllBuiltinPlugins maps the plugin name an operator writes in config to its
// loader constructor. The k8s plugin is named "k8s_psat" to match SPIRE's
// node-attestor naming for projected service account tokens, so the same
// identifier names this auth method on both attestation and exchange surfaces.
var AllBuiltinPlugins = map[string]validator.TokenValidatorLoaderGenerator{
	"github":   github.TokenValidatorLoaderGenerator,
	"gitlab":   gitlab.TokenValidatorLoaderGenerator,
	"k8s_psat": k8s.TokenValidatorLoaderGenerator,
}

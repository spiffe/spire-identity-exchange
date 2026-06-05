package registry

import (
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
)

var AllBuiltinPlugins = map[string]validator.TokenValidatorLoaderGenerator{
	"github": github.TokenValidatorLoaderGenerator,
}

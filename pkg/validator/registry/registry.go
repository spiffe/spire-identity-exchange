package registry

import (
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/gitlab"
)

var AllBuiltinPlugins = map[string]validator.TokenValidatorLoaderGenerator{
	"github": github.TokenValidatorLoaderGenerator,
	"gitlab": gitlab.TokenValidatorLoaderGenerator,
}

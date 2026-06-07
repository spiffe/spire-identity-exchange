package registry

import (
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/gitlab"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/k8s"
)

var AllBuiltinPlugins = map[string]validator.TokenValidatorLoaderGenerator{
	"github":       github.TokenValidatorLoaderGenerator,
	"gitlab":       gitlab.TokenValidatorLoaderGenerator,
	"k8s_sa_token": k8s.TokenValidatorLoaderGenerator,
}

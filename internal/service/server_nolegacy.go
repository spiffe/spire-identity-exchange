//go:build !legacy

package service

import (
	"github.com/spiffe/spire-identity-exchange/internal/config"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// initLegacyAuthHandlers is a no-op when the "legacy" build tag is absent.
// githubOIDC and k8sSAToken remain nil, so MintCertificate dispatch returns
// Unimplemented for those auth methods.
func (h *SpireIdentityExchangeServer) initLegacyAuthHandlers(_ *config.SpireIdentityExchangeConfig, _, _ v.TokenValidator) error {
	return nil
}

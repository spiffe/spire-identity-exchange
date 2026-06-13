package service

import (
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

// SpireClient is the interface for SPIRE server SVID minting, used only by
// legacy code paths (githubOIDC and k8sSAToken). Without the "legacy" build
// tag the field in SpireIdentityExchangeServer is always nil and dispatch
// returns Unimplemented.
type SpireClient interface {
	NewSVIDClient() svidv1.SVIDClient
	Release()
}

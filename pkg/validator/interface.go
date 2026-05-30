package validator

import (
	"context"
	"crypto"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// TokenValidator defines the interface for validating external tokens
// and extracting identity claims. This interface is shared between
// spire-identity-exchange (token exchange service) and SPIRE node
// attestor plugins.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (Claims, error)
}

// KeyProvider provides public keys for JWT signature verification.
// Implementations control caching strategy (on-demand, periodic refresh, etc.).
type KeyProvider interface {
	GetKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// KeySynchronizer defines the interface for background key refresh
// (e.g., periodic JWKS cache updates).
type KeySynchronizer interface {
	Start(ctx context.Context) error
}

// SelectorGenerator generates SPIRE selectors from validated claims.
// Selectors are used for entry matching in both Delegated Identity API
// calls and node attestor responses. The returned selectors use the
// spire-api-sdk types.Selector, so they can be passed directly to
// SPIRE APIs without conversion.
type SelectorGenerator interface {
	GenerateSelectors(claims Claims) []*types.Selector
}

// Metrics defines the interface for recording validator operation metrics.
// Implementations may use Prometheus, OpenTelemetry, or any other backend.
// When nil is passed in Config, metrics collection is silently skipped.
type Metrics interface {
	IncOperationCount(component, plugin, operation, status string)
	ObserveOperationDuration(component, plugin, operation, status string, duration float64)
}

package spiffe

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// WorkloadAPIKeyProvider implements validator.KeyProvider by reading JWT
// authorities from a federated trust domain bundle exposed by the SPIRE Agent
// Workload API.
type WorkloadAPIKeyProvider struct {
	source      *workloadapi.BundleSource
	trustDomain spiffeid.TrustDomain
	metrics     validator.Metrics
}

// NewWorkloadAPIKeyProvider creates a KeyProvider backed by the Workload API.
func NewWorkloadAPIKeyProvider(source *workloadapi.BundleSource, trustDomain spiffeid.TrustDomain, metrics validator.Metrics) *WorkloadAPIKeyProvider {
	return &WorkloadAPIKeyProvider{
		source:      source,
		trustDomain: trustDomain,
		metrics:     metrics,
	}
}

// NewWorkloadAPIBundleSource connects to the agent Workload API at socketAddr.
func NewWorkloadAPIBundleSource(ctx context.Context, socketAddr string) (*workloadapi.BundleSource, error) {
	return workloadapi.NewBundleSource(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)),
	)
}

// GetKey returns the public key for kid from the federated JWT bundle.
func (p *WorkloadAPIKeyProvider) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	now := time.Now()
	statusCode := "OK"
	defer func() {
		if p.metrics != nil {
			p.metrics.ObserveOperationDuration("validator", "spiffe", "fetch_jwt_bundle", statusCode, time.Since(now).Seconds())
			p.metrics.IncOperationCount("validator", "spiffe", "fetch_jwt_bundle", statusCode)
		}
	}()

	if err := ctx.Err(); err != nil {
		statusCode = "error"
		return nil, err
	}

	jwtBundle, err := p.source.GetJWTBundleForTrustDomain(p.trustDomain)
	if err != nil {
		statusCode = "error"
		return nil, fmt.Errorf("failed to get JWT bundle for trust domain %q: %w", p.trustDomain, err)
	}

	key, ok := jwtBundle.FindJWTAuthority(kid)
	if !ok {
		statusCode = "error"
		return nil, fmt.Errorf("no key found for kid=%q in JWT bundle for trust domain %q", kid, p.trustDomain)
	}
	return key, nil
}

// Start waits until the Workload API has delivered an initial bundle update.
func (p *WorkloadAPIKeyProvider) Start(ctx context.Context) error {
	return p.source.WaitUntilUpdated(ctx)
}

// Close releases the Workload API bundle source.
func (p *WorkloadAPIKeyProvider) Close() error {
	return p.source.Close()
}

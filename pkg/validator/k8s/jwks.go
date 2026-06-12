package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"k8s.io/client-go/rest"
)

const (
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	jwksPath          = "/openid/v1/jwks"
	discoveryTimeout  = 10 * time.Second
	maxDiscoveryBytes = 1 << 20 // 1 MiB
)

type oidcDiscoveryDoc struct {
	Issuer string `json:"issuer"`
}

// newJWKSCheckValidator builds the JWKS signature check stage. It reuses
// the same credentials as TokenReview (in-cluster SA token or kubeconfig) to
// reach the API server, discovers the cluster's token issuer, and verifies
// token signatures against the API server's JWKS endpoint via the generic
// jwt.Validator. Keys are cached, so an obviously-invalid token is rejected
// without a TokenReview round-trip and brief API server downtime is tolerated
// for already-cached keys.
//
// Only the self-hosted issuer case is supported: keys are fetched from the API
// server's own /openid/v1/jwks endpoint with the authenticated client, so
// credentials never leave the API server host. External-issuer setups (keys
// served off-cluster) would need an explicit unauthenticated jwksUri, which is
// not yet implemented.
func newJWKSCheckValidator(cfg Config) (validator.TokenValidator, error) {
	restCfg, err := getKubernetesConfig(cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes client config: %w", err)
	}
	httpClient, err := rest.HTTPClientFor(restCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build authenticated http client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	issuer, err := discoverClusterIssuer(ctx, httpClient, restCfg.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to discover cluster issuer: %w", err)
	}

	// Fetch keys from the API server's own JWKS endpoint with the authenticated
	// client rather than the discovered jwks_uri, so the API server credentials
	// and CA are never sent to a different host.
	jwksURL := strings.TrimRight(restCfg.Host, "/") + jwksPath
	keyProvider := jwt.NewKeyProviderWithJWKSURI(jwksURL, httpClient, cfg.Metrics)

	return jwt.NewValidator(jwt.Config{
		IssuerURL:   issuer,
		Audiences:   cfg.Audiences,
		KeyProvider: keyProvider,
		Metrics:     cfg.Metrics,
	})
}

// discoverClusterIssuer fetches the API server's OpenID Connect discovery
// document and returns the issuer that signs service-account tokens. The
// authenticated client is required because the discovery endpoint is not
// exposed anonymously on most clusters.
func discoverClusterIssuer(ctx context.Context, httpClient *http.Client, apiServerHost string) (string, error) {
	configURL := strings.TrimRight(apiServerHost, "/") + oidcDiscoveryPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read discovery document: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d fetching discovery document: %s", resp.StatusCode, string(body))
	}

	var doc oidcDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("failed to parse discovery document: %w", err)
	}
	if doc.Issuer == "" {
		return "", fmt.Errorf("discovery document missing issuer")
	}
	return doc.Issuer, nil
}

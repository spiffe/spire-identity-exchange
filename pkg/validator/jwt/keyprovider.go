package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const (
	openidConfigPath = "/.well-known/openid-configuration"
	cacheTTL         = time.Hour
	maxJWKSBytes     = 1 << 20 // 1 MiB
)

// DefaultKeyProvider implements validator.KeyProvider with on-demand JWKS
// fetching and in-memory caching. The JWKS URL is discovered via the issuer's
// OpenID Connect discovery endpoint (/.well-known/openid-configuration).
// It is suitable for standalone tools and plugins; production servers may
// inject their own KeyProvider with background refresh and fail-closed semantics.
type DefaultKeyProvider struct {
	issuerURL  string
	httpClient *http.Client
	metrics    validator.Metrics

	mu    sync.RWMutex
	cache *jwksCache
}

type jwksCache struct {
	keys    map[string]crypto.PublicKey
	jwksURI string
	expiry  time.Time
}

// NewDefaultKeyProvider creates a KeyProvider that fetches JWKS on demand
// from the issuer's /.well-known/jwks endpoint.
func NewDefaultKeyProvider(issuerURL string, httpClient *http.Client, metrics validator.Metrics) *DefaultKeyProvider {
	return &DefaultKeyProvider{
		issuerURL:  issuerURL,
		httpClient: httpClient,
		metrics:    metrics,
	}
}

// GetKey returns the public key for the given kid. Implements validator.KeyProvider.
func (p *DefaultKeyProvider) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	p.mu.RLock()
	if p.cache != nil && time.Now().Before(p.cache.expiry) {
		if key, ok := p.cache.keys[kid]; ok {
			p.mu.RUnlock()
			return key, nil
		}
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock.
	if p.cache != nil && time.Now().Before(p.cache.expiry) {
		if key, ok := p.cache.keys[kid]; ok {
			return key, nil
		}
	}

	// Reuse cached jwks_uri if available, otherwise discover it.
	jwksURL := ""
	if p.cache != nil {
		jwksURL = p.cache.jwksURI
	}
	if jwksURL == "" {
		var err error
		jwksURL, err = p.discoverJWKSURI(ctx)
		if err != nil {
			return nil, fmt.Errorf("OIDC discovery failed: %w", err)
		}
	}

	keys, err := p.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}

	p.cache = &jwksCache{keys: keys, jwksURI: jwksURL, expiry: time.Now().Add(cacheTTL)}

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("no key found for kid=%q in JWKS", kid)
	}
	return key, nil
}

// openidConfiguration represents the relevant fields from an OpenID Connect
// discovery document.
type openidConfiguration struct {
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKSURI fetches the OpenID Connect discovery document from the
// issuer and returns the jwks_uri.
func (p *DefaultKeyProvider) discoverJWKSURI(ctx context.Context) (string, error) {
	configURL := strings.TrimRight(p.issuerURL, "/") + openidConfigPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read discovery document: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d fetching discovery document: %s", resp.StatusCode, string(body))
	}

	var config openidConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to parse discovery document: %w", err)
	}
	if config.JWKSURI == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}

	return config.JWKSURI, nil
}

func (p *DefaultKeyProvider) fetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
	now := time.Now()
	statusCode := "OK"
	defer func() {
		if p.metrics != nil {
			p.metrics.ObserveOperationDuration("validator", "jwt", "fetch_jwks", statusCode, time.Since(now).Seconds())
			p.metrics.IncOperationCount("validator", "jwt", "fetch_jwks", statusCode)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		statusCode = "InvalidArgument"
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		statusCode = "Internal"
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		statusCode = "Internal"
		return nil, fmt.Errorf("HTTP %d fetching JWKS: %s", resp.StatusCode, string(body))
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		statusCode = "Internal"
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		pub := jwk.Public().Key
		switch key := pub.(type) {
		case *rsa.PublicKey:
			keys[jwk.KeyID] = key
		case *ecdsa.PublicKey:
			keys[jwk.KeyID] = key
		default:
			continue
		}
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid signing keys found in JWKS from %s", jwksURL)
	}

	return keys, nil
}

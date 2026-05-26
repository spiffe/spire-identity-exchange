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
)

const (
	jwksPath     = "/.well-known/jwks"
	cacheTTL     = time.Hour
	maxJWKSBytes = 1 << 20 // 1 MiB
)

// DefaultKeyProvider implements validator.KeyProvider with on-demand JWKS
// fetching and in-memory caching. It is suitable for standalone tools and
// plugins; production servers may inject their own KeyProvider with
// background refresh and fail-closed semantics.
type DefaultKeyProvider struct {
	issuerURL  string
	httpClient *http.Client

	mu    sync.RWMutex
	cache *jwksCache
}

type jwksCache struct {
	keys   map[string]crypto.PublicKey
	expiry time.Time
}

// NewDefaultKeyProvider creates a KeyProvider that fetches JWKS on demand
// from the issuer's /.well-known/jwks endpoint.
func NewDefaultKeyProvider(issuerURL string, httpClient *http.Client) *DefaultKeyProvider {
	return &DefaultKeyProvider{
		issuerURL:  issuerURL,
		httpClient: httpClient,
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

	jwksURL := strings.TrimRight(p.issuerURL, "/") + jwksPath
	keys, err := p.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}

	p.cache = &jwksCache{keys: keys, expiry: time.Now().Add(cacheTTL)}

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("no key found for kid=%q in JWKS", kid)
	}
	return key, nil
}

func (p *DefaultKeyProvider) fetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching JWKS: %s", resp.StatusCode, string(body))
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
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

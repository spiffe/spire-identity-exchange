package github

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

	"github.com/golang-jwt/jwt/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const (
	DefaultIssuer = "https://token.actions.githubusercontent.com"
	jwksPath      = "/.well-known/jwks"
	cacheTTL      = time.Hour
	clockLeeway   = 30 * time.Second
	httpTimeout   = 10 * time.Second
	maxJWKSBytes  = 1 << 20 // 1 MiB
)

// Config holds configuration for the GitHub OIDC validator.
type Config struct {
	IssuerURL               string
	Audiences               []string
	AllowedRepositoryOwners []string
	AllowedRepositories     []string
	HTTPClient              *http.Client
	// KeyProvider allows injecting a custom key provider (e.g., one with
	// background refresh and fail-closed semantics). If nil, a default
	// on-demand JWKS fetching provider is used.
	KeyProvider validator.KeyProvider
}

// Validator validates GitHub Actions OIDC tokens.
// It implements validator.TokenValidator and validator.SelectorGenerator.
type Validator struct {
	issuerURL               string
	audiences               []string
	allowedRepositoryOwners []string
	allowedRepositories     []string
	keyProvider             validator.KeyProvider
}

// NewValidator creates a new GitHub OIDC validator.
func NewValidator(cfg Config) (*Validator, error) {
	issuer := cfg.IssuerURL
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if len(cfg.Audiences) == 0 {
		return nil, fmt.Errorf("at least one audience must be configured")
	}
	if len(cfg.AllowedRepositories) == 0 && len(cfg.AllowedRepositoryOwners) == 0 {
		return nil, fmt.Errorf("at least one of allowed_repositories or allowed_repository_owners must be configured")
	}

	keyProvider := cfg.KeyProvider
	if keyProvider == nil {
		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: httpTimeout}
		}
		keyProvider = newDefaultKeyProvider(issuer, client)
	}

	return &Validator{
		issuerURL:               issuer,
		audiences:               cfg.Audiences,
		allowedRepositoryOwners: cfg.AllowedRepositoryOwners,
		allowedRepositories:     cfg.AllowedRepositories,
		keyProvider:             keyProvider,
	}, nil
}

// Validate validates a GitHub Actions OIDC token and returns common claims.
// Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string) (validator.Claims, error) {
	claims, err := v.validateToken(ctx, token)
	if err != nil {
		return nil, err
	}

	if err := v.checkAllowLists(claims); err != nil {
		return nil, err
	}

	return claims.ToCommonClaims(), nil
}

func (v *Validator) validateToken(ctx context.Context, rawToken string) (*Claims, error) {
	kid, err := extractKID(rawToken)
	if err != nil {
		return nil, err
	}

	pubKey, err := v.keyProvider.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for kid=%q: %w", kid, err)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// GitHub currently uses RS256 but may switch to ECDSA.
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	},
		jwt.WithIssuer(v.issuerURL),
		jwt.WithLeeway(clockLeeway),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Validate audience: token must contain at least one of the configured audiences.
	tokenAud, err := claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("failed to get audience from token: %w", err)
	}
	if !v.validateAudiences(tokenAud) {
		return nil, fmt.Errorf("audience mismatch: token has %v, expected one of %v", tokenAud, v.audiences)
	}

	return claims, nil
}

func (v *Validator) validateAudiences(tokenAudiences []string) bool {
	for _, tokenAud := range tokenAudiences {
		for _, configuredAud := range v.audiences {
			if tokenAud == configuredAud {
				return true
			}
		}
	}
	return false
}

func extractKID(rawToken string) (string, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token header: %w", err)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return "", fmt.Errorf("token header missing or invalid 'kid' field")
	}
	return kid, nil
}

// checkAllowLists enforces AND logic: when both lists are configured,
// the token must match both owner and repository.
func (v *Validator) checkAllowLists(claims *Claims) error {
	if len(v.allowedRepositoryOwners) > 0 {
		if !isValueAllowed(claims.RepositoryOwner, v.allowedRepositoryOwners) {
			return fmt.Errorf("repository owner %q is not in the allowed list", claims.RepositoryOwner)
		}
	}
	if len(v.allowedRepositories) > 0 {
		if !isValueAllowed(claims.Repository, v.allowedRepositories) {
			return fmt.Errorf("repository %q is not in the allowed list", claims.Repository)
		}
	}
	return nil
}

// isValueAllowed checks if a value matches any of the allowed patterns.
// Supports wildcard suffix matching (e.g., "my-org/*" matches "my-org/any-repo").
func isValueAllowed(value string, allowedValues []string) bool {
	for _, av := range allowedValues {
		if strings.Contains(av, "*") {
			pattern := strings.TrimSuffix(av, "*")
			if strings.HasPrefix(value, pattern) {
				return true
			}
		} else if value == av {
			return true
		}
	}
	return false
}

// defaultKeyProvider implements validator.KeyProvider with on-demand JWKS
// fetching and in-memory caching.
type defaultKeyProvider struct {
	issuerURL  string
	httpClient *http.Client

	mu    sync.RWMutex
	cache *jwksCache
}

type jwksCache struct {
	keys   map[string]crypto.PublicKey
	expiry time.Time
}

func newDefaultKeyProvider(issuerURL string, httpClient *http.Client) *defaultKeyProvider {
	return &defaultKeyProvider{
		issuerURL:  issuerURL,
		httpClient: httpClient,
	}
}

// GetKey returns the public key for the given kid. Implements validator.KeyProvider.
func (p *defaultKeyProvider) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
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

func (p *defaultKeyProvider) fetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, error) {
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

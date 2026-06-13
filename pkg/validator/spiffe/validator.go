// Package spiffe provides a SPIFFE SVID JWT validator plugin for validating
// incoming SPIFFE Identity SVID JWTs and generating selectors for token exchange.
package spiffe

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/url"
    "regexp"

    "github.com/spiffe/go-spiffe/v2/spiffeid"
    jwtauth "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
    return &Config{}, nil
}

// Config holds configuration for the SPIFFE SVID validator.
type Config struct {
	IssuerURL    string   `json:"issuerURL"`
	DiscoveryURL string   `json:"discoveryURL"`
	Audiences    []string `json:"audiences"`
	TrustDomain  string   `json:"trustDomain"`
	PathPatterns []string `json:"pathPatterns"`
	// KeyProvider allows injecting a custom key provider (e.g., one with
	// background refresh and fail-closed semantics). If nil, a default
	// on-demand JWKS fetching provider is used.
	KeyProvider validator.KeyProvider `json:"-"`
	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics `json:"-"`
	// AllowHTTP permits http:// issuer URLs for local testing (e.g., mock OIDC servers).
	// Must not be enabled in production.
	AllowHTTP bool `json:"-"`
}

func (c *Config) Unmarshal(raw json.RawMessage) error {
    return json.Unmarshal(raw, c)
}

func (c *Config) ValidateConfig() error {
    if c.IssuerURL == "" {
        return errors.New("issuer URL must not be empty")
    }
	if err := jwtauth.ValidateIssuerURL(c.IssuerURL, c.AllowHTTP); err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}
    if len(c.Audiences) == 0 {
        return errors.New("at least one audience must be specified")
    }
    if c.TrustDomain == "" {
        return errors.New("trust domain must not be empty")
    }
    if len(c.PathPatterns) == 0 {
        return errors.New("at least one path pattern must be specified")
    }
    return nil
}

func (c *Config) NewValidator() (validator.TokenValidatorAndSelectorGenerator, error) {
    return NewValidator(*c)
}

// Validator validates SPIFFE SVID JWTs and generates selectors for token exchange.
// It implements validator.TokenValidator and validator.SelectorGenerator.
type Validator struct {
    jwtValidator *jwtauth.Validator
    config       Config
}

// NewValidator creates a new SPIFFE SVID validator.
func NewValidator(cfg Config) (*Validator, error) {
    _, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
    if err != nil {
        return nil, fmt.Errorf("invalid trust domain: %w", err)
    }

    discoveryURL := cfg.DiscoveryURL
    if discoveryURL == "" {
        discoveryURL = cfg.IssuerURL
    }
    jv, err := jwtauth.NewValidator(jwtauth.Config{
        IssuerURL:    cfg.IssuerURL,
        DiscoveryURL: discoveryURL,
        Audiences:    cfg.Audiences,
        KeyProvider:  cfg.KeyProvider,
        AllowHTTP:    cfg.AllowHTTP,
        Metrics:      cfg.Metrics,
    })
    if err != nil {
        return nil, err
    }

    return &Validator{
        jwtValidator: jv,
        config:       cfg,
    }, nil
}

// Validate validates a SPIFFE SVID JWT token and returns claims.
// Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
    claims, err := v.jwtValidator.Validate(ctx, token, purpose)
    if err != nil {
        return nil, err
    }

    raw := claims.GetRaw()
    if err := v.checkAllowLists(raw); err != nil {
        return nil, err
    }

    return claims, nil
}

// checkAllowLists enforces the configured trust domain and path patterns
// against the validated claims. The JWT sub claim is URL-decoded before
// parsing as a SPIFFE ID.
func (v *Validator) checkAllowLists(raw map[string]interface{}) error {
    // Extract and URL-decode the sub claim
    subRaw, ok := raw["sub"]
    if !ok {
        return errors.New("token is missing required 'sub' claim")
    }
    sub, ok := subRaw.(string)
    if !ok {
        return errors.New("token 'sub' claim must be a string")
    }

    // URL-decode the sub claim (SPIFFE IDs may have encoded segments)
    subDecoded, err := url.QueryUnescape(sub)
    if err != nil {
        return fmt.Errorf("failed to URL-decode 'sub' claim: %w", err)
    }

    // Parse the decoded sub as a SPIFFE ID
    spiffeID, err := spiffeid.FromString(subDecoded)
    if err != nil {
        return fmt.Errorf("failed to parse SPIFFE ID from 'sub': %w", err)
    }

    // Validate trust domain
    td := spiffeID.TrustDomain().String()
    if td != v.config.TrustDomain {
        return fmt.Errorf("token SPIFFE ID trust domain %q does not match configured trust domain %q",
            td, v.config.TrustDomain)
    }

    // Validate path using regex patterns
    path := spiffeID.Path()
    matched := false
    for _, pattern := range v.config.PathPatterns {
        re, err := regexp.Compile(pattern)
        if err != nil {
            return fmt.Errorf("failed to compile path pattern %q: %w", pattern, err)
        }
        if re.MatchString(path) {
            matched = true
            break
        }
    }
    if !matched {
        return fmt.Errorf("token SPIFFE ID path %q does not match any allowed path patterns", path)
    }

    return nil
}


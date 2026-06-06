// Package jwt provides a reusable JWT token validator that can be used as
// a building block for provider-specific validators (GitHub, GitLab, K8s, etc.).
package jwt

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

const (
	defaultClockLeeway = 30 * time.Second
	defaultHTTPTimeout = 10 * time.Second
)

// Config holds configuration for the generic JWT validator.
type Config struct {
	IssuerURL string
	Audiences []string
	// KeyProvider allows injecting a custom key provider (e.g., one with
	// background refresh and fail-closed semantics). If nil, a default
	// on-demand JWKS fetching provider is used.
	KeyProvider validator.KeyProvider
	HTTPClient  *http.Client
	// AllowHTTP permits http:// issuer URLs for local testing (e.g., mock OIDC servers).
	// Must not be enabled in production.
	AllowHTTP bool
	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics
}

// Validator validates JWT tokens by verifying signatures, issuer, audience,
// and expiration. It returns validated claims via the validator.Claims interface.
type Validator struct {
	issuerURL   string
	audiences   []string
	keyProvider validator.KeyProvider
	metrics     validator.Metrics
}

// NewValidator creates a new generic JWT validator.
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL must not be empty")
	}
	if err := ValidateIssuerURL(cfg.IssuerURL, cfg.AllowHTTP); err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}
	if len(cfg.Audiences) == 0 {
		return nil, fmt.Errorf("at least one audience must be configured")
	}

	keyProvider := cfg.KeyProvider
	if keyProvider == nil {
		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: defaultHTTPTimeout}
		}
		keyProvider = NewDefaultKeyProvider(cfg.IssuerURL, client, cfg.Metrics)
	}

	return &Validator{
		issuerURL:   cfg.IssuerURL,
		audiences:   cfg.Audiences,
		keyProvider: keyProvider,
		metrics:     cfg.Metrics,
	}, nil
}

// Validate validates a JWT token and returns claims.
// Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string) (validator.Claims, error) {
	now := time.Now()
	statusCode := "OK"
	defer func() {
		if v.metrics != nil {
			v.metrics.ObserveOperationDuration("validator", "jwt", "validate_token", statusCode, time.Since(now).Seconds())
			v.metrics.IncOperationCount("validator", "jwt", "validate_token", statusCode)
		}
	}()

	kid, err := extractKID(token)
	if err != nil {
		statusCode = "InvalidArgument"
		return nil, err
	}

	pubKey, err := v.keyProvider.GetKey(ctx, kid)
	if err != nil {
		statusCode = "Internal"
		return nil, fmt.Errorf("failed to get public key for kid=%q: %w", kid, err)
	}

	keyFunc := func(t *gojwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *gojwt.SigningMethodRSA, *gojwt.SigningMethodECDSA:
			// ok
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pubKey, nil
	}
	parserOpts := []gojwt.ParserOption{
		gojwt.WithIssuer(v.issuerURL),
		gojwt.WithLeeway(defaultClockLeeway),
		gojwt.WithExpirationRequired(),
	}

	// Parse with RegisteredClaims for structured validation.
	regClaims := &gojwt.RegisteredClaims{}
	parsed, err := gojwt.ParseWithClaims(token, regClaims, keyFunc, parserOpts...)
	if err != nil {
		statusCode = "InvalidArgument"
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !parsed.Valid {
		statusCode = "InvalidArgument"
		return nil, fmt.Errorf("token is not valid")
	}

	// Validate audience: token must contain at least one of the configured audiences.
	tokenAud, err := regClaims.GetAudience()
	if err != nil {
		statusCode = "InvalidArgument"
		return nil, fmt.Errorf("failed to get audience from token: %w", err)
	}
	if !v.validateAudiences(tokenAud) {
		statusCode = "PermissionDenied"
		return nil, fmt.Errorf("audience mismatch: token has %v, expected one of %v", tokenAud, v.audiences)
	}

	// Parse into MapClaims to capture all claims for GetRaw().
	mapClaims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(token, mapClaims); err != nil {
		statusCode = "Internal"
		return nil, fmt.Errorf("failed to parse raw claims: %w", err)
	}

	// Build JWTClaims from registered claims + raw map.
	var expiry int64
	if regClaims.ExpiresAt != nil {
		expiry = regClaims.ExpiresAt.Unix()
	}
	var notBefore int64
	if regClaims.NotBefore != nil {
		notBefore = regClaims.NotBefore.Unix()
	}
	var issuedAt int64
	if regClaims.IssuedAt != nil {
		issuedAt = regClaims.IssuedAt.Unix()
	}
	aud := []string{}
	if regClaims.Audience != nil {
		aud = []string(regClaims.Audience)
	}

	return &validator.JWTClaims{
		Issuer:    regClaims.Issuer,
		Subject:   regClaims.Subject,
		Audience:  aud,
		Expiry:    expiry,
		NotBefore: notBefore,
		IssuedAt:  issuedAt,
		JTI:       regClaims.ID,
		Raw:       map[string]interface{}(mapClaims),
	}, nil
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
	parser := gojwt.NewParser()
	token, _, err := parser.ParseUnverified(rawToken, gojwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse token header: %w", err)
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return "", fmt.Errorf("token header missing or invalid 'kid' field")
	}
	return kid, nil
}

// ValidateIssuerURL validates the issuer URL format and scheme.
func ValidateIssuerURL(issuer string, allowHTTP bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	isHTTPS := u.Scheme == "https"
	isLocalhost := u.Scheme == "http" && u.Hostname() == "localhost"
	isAllowedHTTP := allowHTTP && u.Scheme == "http"
	if !isHTTPS && !isLocalhost && !isAllowedHTTP {
		return fmt.Errorf("scheme must be https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("host must not be empty")
	}
	if u.RawQuery != "" {
		return fmt.Errorf("query parameters are not allowed")
	}
	if u.Fragment != "" {
		return fmt.Errorf("fragment is not allowed")
	}
	return nil
}

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
	// DiscoveryURL is the base URL used for OIDC discovery of the JWKS endpoint.
	// If empty, it defaults to IssuerURL.
	DiscoveryURL string
	Audiences    []string
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
	issuerURL    string
	discoveryURL string
	audiences    []string
	keyProvider  validator.KeyProvider
	metrics      validator.Metrics
}

// NewValidator creates a new generic JWT validator.
func NewValidator(cfg Config) (*Validator, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL must not be empty")
	}
	// Format only here. Whether the issuer's scheme is constrained depends on
	// whether it also serves as the discovery URL, decided below.
	if err := ValidateIssuerFormat(cfg.IssuerURL); err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}
	if len(cfg.Audiences) == 0 {
		return nil, fmt.Errorf("at least one audience must be configured")
	}

	// The discovery URL is dereferenced, so it carries the scheme requirement.
	// When it is not configured the issuer is used for discovery and inherits
	// that requirement -- reported against the field the operator actually set.
	discoveryURL := cfg.DiscoveryURL
	errLabel := "invalid discovery URL"
	if discoveryURL == "" {
		discoveryURL = cfg.IssuerURL
		errLabel = "invalid issuer URL"
	}
	if err := ValidateIssuerURL(discoveryURL, cfg.AllowHTTP); err != nil {
		return nil, fmt.Errorf("%s: %w", errLabel, err)
	}

	keyProvider := cfg.KeyProvider
	if keyProvider == nil {
		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: defaultHTTPTimeout}
		}
		keyProvider = NewDefaultKeyProvider(discoveryURL, client, cfg.Metrics, WithAllowHTTP(cfg.AllowHTTP))
	}

	return &Validator{
		issuerURL:    cfg.IssuerURL,
		discoveryURL: discoveryURL,
		audiences:    cfg.Audiences,
		keyProvider:  keyProvider,
		metrics:      cfg.Metrics,
	}, nil
}

// Validate validates a JWT token and returns claims.
// Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string, _ validator.Purpose) (validator.Claims, error) {
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

// validateIssuerShape validates the parts of a URL that must hold whether or not
// it will be dereferenced.
func validateIssuerShape(u *url.URL) error {
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

// ValidateIssuerFormat validates the shape of an issuer identifier. It
// deliberately does NOT constrain the scheme: an issuer is compared against the
// token's `iss` claim -- a StringOrURI per RFC 7519 section 4.1.1, with no
// scheme requirement -- and is never dereferenced. The https requirement in
// OpenID Connect Discovery exists because the issuer URL is fetched there to
// retrieve the provider configuration; where the key source is configured
// out-of-band, that rationale does not apply.
//
// Use ValidateIssuerURL for a URL that will actually be requested.
func ValidateIssuerFormat(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	return validateIssuerShape(u)
}

// ValidateIssuerURL validates a URL that will be dereferenced: the format checks
// of ValidateIssuerFormat plus a requirement that the transport be https (or
// http to localhost, or http when allowHTTP is set).
func ValidateIssuerURL(issuer string, allowHTTP bool) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	if err := validateFetchableScheme(u, allowHTTP); err != nil {
		return err
	}
	return validateIssuerShape(u)
}

// ValidateJWKSURL validates a jwks_uri taken from a discovery document.
//
// A discovery document is remote input, and its jwks_uri is where the signing
// keys are actually fetched from. Authenticating the document and then following
// it to a plaintext endpoint protects the pointer and not the keys, which is the
// half that decides whether a token is trusted; so the URL the keys come from is
// held to the same transport requirement as the URL the document came from.
//
// Deliberately NOT ValidateIssuerURL: that also rejects query parameters, which
// is right for an issuer identifier and wrong here. Azure AD B2C publishes a
// jwks_uri carrying a `p=<policy>` query, and it is a perfectly ordinary URL to
// fetch.
func ValidateJWKSURL(jwksURI string, allowHTTP bool) error {
	u, err := url.Parse(jwksURI)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}
	if u.Host == "" {
		return fmt.Errorf("host must not be empty")
	}
	return validateFetchableScheme(u, allowHTTP)
}

// validateFetchableScheme is the transport requirement shared by every URL this
// package dereferences. Shared so the issuer and the jwks_uri cannot drift into
// disagreeing about what counts as safe to fetch.
//
// Note the exemption is the literal hostname "localhost" and not 127.0.0.1 or
// ::1. That is the pre-existing behaviour and is left alone here: widening it
// belongs in a change about the exemption, not in one about the jwks_uri.
func validateFetchableScheme(u *url.URL, allowHTTP bool) error {
	isHTTPS := u.Scheme == "https"
	isLocalhost := u.Scheme == "http" && u.Hostname() == "localhost"
	isAllowedHTTP := allowHTTP && u.Scheme == "http"
	if !isHTTPS && !isLocalhost && !isAllowedHTTP {
		return fmt.Errorf("scheme must be https (got %q)", u.Scheme)
	}
	return nil
}

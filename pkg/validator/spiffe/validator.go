// Package spiffe provides a SPIFFE SVID JWT validator plugin for validating
// incoming SPIFFE Identity SVID JWTs and generating selectors for token exchange.
package spiffe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtauth "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"go.yaml.in/yaml/v3"
)

const (
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	discoveryTimeout  = 10 * time.Second
	maxDiscoveryBytes = 1 << 20 // 1 MiB
)

type oidcDiscoveryDoc struct {
	JWKSURI string `json:"jwks_uri"`
}

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
    return &Config{}, nil
}

// Config holds configuration for the SPIFFE SVID validator.
type Config struct {
	IssuerURL    string   `yaml:"issuerURL"`
	DiscoveryURL string   `yaml:"discoveryURL"`
	Audiences    []string `yaml:"audiences"`
	TrustDomain  string   `yaml:"trustDomain"`
	PathPatterns []string `yaml:"pathPatterns"`
	// ConnectWithTrustBundle determines if the plugin uses its retrieved
	// trust bundle to validate the remote OIDC discovery endpoint's TLS certs.
	ConnectWithTrustBundle bool `yaml:"connectWithTrustBundle"`
	// AgentWorkloadSocketPath specifies a custom UDS socket path for reaching the
	// SPIFFE Workload API. Required if ConnectWithTrustBundle is enabled.
	AgentWorkloadSocketPath string `yaml:"agentWorkloadSocketPath"`
	// KeyProvider allows injecting a custom key provider (e.g., one with
	// background refresh and fail-closed semantics). If nil, a default
	// on-demand JWKS fetching provider is used.
	KeyProvider validator.KeyProvider `yaml:"-"`
	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics `yaml:"-"`
	// AllowHTTP permits http:// issuer URLs for local testing (e.g., mock OIDC servers).
	// Must not be enabled in production.
	AllowHTTP bool `yaml:"-"`
}

func (c *Config) Unmarshal(raw *yaml.Node) error {
    return raw.Decode(c)
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
	if c.ConnectWithTrustBundle && c.AgentWorkloadSocketPath == "" {
		return errors.New("agent workload socket path must be specified when connectWithTrustBundle is enabled")
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

    keyProvider := cfg.KeyProvider
    if keyProvider == nil && cfg.ConnectWithTrustBundle && cfg.TrustDomain != "" {
        td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
        if err != nil {
            return nil, fmt.Errorf("invalid trust domain: %w", err)
        }

        socketAddr := "unix://" + strings.TrimPrefix(cfg.AgentWorkloadSocketPath, "unix://")
        source, err := workloadapi.NewX509Source(
            context.Background(),
            workloadapi.WithClientOptions(workloadapi.WithAddress(socketAddr)),
        )
        if err != nil {
            return nil, fmt.Errorf("failed to create SPIFFE X509 source: %w", err)
        }

        tlsCfg := tlsconfig.TLSClientConfig(source, tlsconfig.AuthorizeMemberOf(td))
        httpClient := &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: tlsCfg,
            },
            Timeout: discoveryTimeout,
        }

        ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
        defer cancel()

        configURL := strings.TrimRight(discoveryURL, "/") + oidcDiscoveryPath
        req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
        if err != nil {
            return nil, fmt.Errorf("failed to create discovery request: %w", err)
        }

        resp, err := httpClient.Do(req)
        if err != nil {
            return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes))
        if err != nil {
            return nil, fmt.Errorf("failed to read discovery document: %w", err)
        }
        if resp.StatusCode != http.StatusOK {
            return nil, fmt.Errorf("HTTP %d fetching discovery document: %s", resp.StatusCode, string(body))
        }

        var doc oidcDiscoveryDoc
        if err := json.Unmarshal(body, &doc); err != nil {
            return nil, fmt.Errorf("failed to parse discovery document: %w", err)
        }
        if doc.JWKSURI == "" {
            return nil, fmt.Errorf("discovery document missing jwks_uri")
        }

        keyProvider = jwtauth.NewKeyProviderWithJWKSURI(doc.JWKSURI, httpClient, cfg.Metrics)
    }

   jv, err := jwtauth.NewValidator(jwtauth.Config{
        IssuerURL:             cfg.IssuerURL,
        DiscoveryURL:          discoveryURL,
        Audiences:             cfg.Audiences,
        KeyProvider:           keyProvider,
        AllowHTTP:             cfg.AllowHTTP,
        Metrics:               cfg.Metrics,
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

    // Parse the decoded sub as a SPIFFE ID
    spiffeID, err := spiffeid.FromString(sub)
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

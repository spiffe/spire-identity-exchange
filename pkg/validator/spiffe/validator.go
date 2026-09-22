// Package spiffe provides a SPIFFE SVID JWT validator plugin for validating
// incoming SPIFFE Identity SVID JWTs and generating selectors for token exchange.
package spiffe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtauth "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/spiffetls"
	"go.yaml.in/yaml/v3"
)

const (
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	discoveryTimeout  = 10 * time.Second
	maxDiscoveryBytes = 1 << 20 // 1 MiB

	KeySourceOIDC        = "oidc"
	KeySourceWorkloadAPI = "workload_api"
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
	// Any workload in TrustDomain is accepted; set DiscoverySPIFFEID to narrow
	// that to one identity.
	ConnectWithTrustBundle bool `yaml:"connectWithTrustBundle"`
	// DiscoverySPIFFEID, when set, validates the discovery endpoint's TLS
	// against the SPIFFE trust bundle and requires it to present exactly this
	// SPIFFE ID. Implies ConnectWithTrustBundle, and takes precedence over it:
	// both authorize the same URI SAN, and this one is narrower.
	//
	// Note that SPIFFE TLS does not verify the DNS name, so the host in
	// DiscoveryURL is an address and this is the identity.
	DiscoverySPIFFEID string `yaml:"discoverySPIFFEID"`
	// AgentWorkloadSocketPath specifies a custom UDS socket path for reaching the
	// SPIFFE Workload API. Required if ConnectWithTrustBundle, DiscoverySPIFFEID
	// or KeySource workload_api is enabled -- from here or, when this is unset,
	// from the server-level spire.agentWorkloadSocketPath.
	AgentWorkloadSocketPath string `yaml:"agentWorkloadSocketPath"`
	// defaultWorkloadAPISocketPath is supplied by the config loader from the
	// server-level setting; see SetDefaultWorkloadAPISocketPath.
	defaultWorkloadAPISocketPath string `yaml:"-"`
	// KeySource selects where JWT verification keys are fetched from. Defaults to
	// oidc (HTTP OIDC discovery + JWKS). Use workload_api to read JWT authorities
	// from a federated trust domain bundle on the agent Workload API.
	KeySource string `yaml:"keySource"`
	// JWKSTrustDomain selects which federated trust domain's JWT bundle to use
	// when KeySource is workload_api. Defaults to TrustDomain when empty.
	JWKSTrustDomain string `yaml:"jwksTrustDomain"`
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
	if c.DiscoveryURL == "" {
		// The issuer doubles as the discovery URL, so it will be fetched and
		// inherits the scheme requirement.
		if err := jwtauth.ValidateIssuerURL(c.IssuerURL, c.AllowHTTP); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
	} else {
		// The issuer is only compared against the `iss` claim; the discovery URL
		// is the one dereferenced.
		if err := jwtauth.ValidateIssuerFormat(c.IssuerURL); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
		if err := jwtauth.ValidateIssuerURL(c.DiscoveryURL, c.AllowHTTP); err != nil {
			return fmt.Errorf("invalid discovery URL: %w", err)
		}
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
	keySource := c.keySource()
	if keySource != KeySourceOIDC && keySource != KeySourceWorkloadAPI {
		return fmt.Errorf("unsupported keySource %q: must be %q or %q", c.KeySource, KeySourceOIDC, KeySourceWorkloadAPI)
	}
	if c.ConnectWithTrustBundle && keySource == KeySourceWorkloadAPI {
		return errors.New("connectWithTrustBundle cannot be used with keySource workload_api")
	}
	if err := spiffetls.ValidateDiscoverySPIFFEID(c.DiscoverySPIFFEID); err != nil {
		return err
	}
	if c.trustBundleEnabled() && c.workloadAPISocketPath() == "" {
		return errors.New("a workload API socket path must be available when connectWithTrustBundle or discoverySPIFFEID is set; " +
			"set agentWorkloadSocketPath on the plugin or spire.agentWorkloadSocketPath on the server")
	}
	if keySource == KeySourceWorkloadAPI && c.workloadAPISocketPath() == "" {
		return errors.New("a workload API socket path must be available when keySource is workload_api; " +
			"set agentWorkloadSocketPath on the plugin or spire.agentWorkloadSocketPath on the server")
	}
	if c.JWKSTrustDomain != "" {
		if _, err := spiffeid.TrustDomainFromString(c.JWKSTrustDomain); err != nil {
			return fmt.Errorf("invalid jwksTrustDomain: %w", err)
		}
	}
	return nil
}

// SetDefaultWorkloadAPISocketPath implements validator.WorkloadAPIDefaulter.
func (c *Config) SetDefaultWorkloadAPISocketPath(path string) {
	c.defaultWorkloadAPISocketPath = path
}

// workloadAPISocketPath resolves the plugin-level path against the server-level
// default. May be empty.
func (c *Config) workloadAPISocketPath() string {
	return spiffetls.ResolveSocketPath(c.AgentWorkloadSocketPath, c.defaultWorkloadAPISocketPath)
}

// trustBundleEnabled reports whether the discovery endpoint's TLS should be
// verified against the SPIFFE trust bundle.
func (c *Config) trustBundleEnabled() bool {
	return c.ConnectWithTrustBundle || c.DiscoverySPIFFEID != ""
}

func (c *Config) keySource() string {
	if c.KeySource == "" {
		return KeySourceOIDC
	}
	return c.KeySource
}

func (c *Config) jwksTrustDomain() string {
	if c.JWKSTrustDomain != "" {
		return c.JWKSTrustDomain
	}
	return c.TrustDomain
}

func (c *Config) NewValidator() (validator.TokenValidatorAndSelectorGenerator, error) {
    return NewValidator(*c)
}

// Validator validates SPIFFE SVID JWTs and generates selectors for token exchange.
// It implements validator.TokenValidator and validator.SelectorGenerator.
type Validator struct {
	jwtValidator *jwtauth.Validator
	config       Config
	keySync validator.KeySynchronizer
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
	var keySync validator.KeySynchronizer
	if keyProvider == nil && cfg.keySource() == KeySourceWorkloadAPI {
		socketAddr := workloadSocketAddr(cfg.workloadAPISocketPath())
		bundleSource, err := NewWorkloadAPIBundleSource(context.Background(), socketAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create SPIFFE bundle source: %w", err)
		}

		jwksTD, err := spiffeid.TrustDomainFromString(cfg.jwksTrustDomain())
		if err != nil {
			bundleSource.Close()
			return nil, fmt.Errorf("invalid jwks trust domain: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
		defer cancel()
		if err := bundleSource.WaitUntilUpdated(ctx); err != nil {
			bundleSource.Close()
			return nil, fmt.Errorf("failed to receive initial JWT bundle from workload API: %w", err)
		}

		wlProvider := NewWorkloadAPIKeyProvider(bundleSource, jwksTD, cfg.Metrics)
		keyProvider = wlProvider
		keySync = wlProvider
	}
	if keyProvider == nil && cfg.trustBundleEnabled() && cfg.TrustDomain != "" {
        // An exact DiscoverySPIFFEID wins over trust-domain membership; both
        // authorize the same URI SAN and the ID is narrower.
        authorizer, err := spiffetls.AuthorizerFor(cfg.DiscoverySPIFFEID, cfg.TrustDomain)
        if err != nil {
            return nil, err
        }

        httpClient, err := spiffetls.NewTrustBundleHTTPClient(cfg.workloadAPISocketPath(), authorizer, discoveryTimeout)
        if err != nil {
            return nil, err
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
        // The document arrived over SPIFFE-authenticated TLS; the URL inside it
        // did not. Following it to a plaintext endpoint would authenticate the
        // pointer and leave the keys -- the thing that decides whether a token
        // is trusted -- open to substitution by anyone on the path.
        if err := jwtauth.ValidateJWKSURL(doc.JWKSURI, cfg.AllowHTTP); err != nil {
            return nil, fmt.Errorf("discovery document advertised an unusable jwks_uri %q: %w", doc.JWKSURI, err)
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
		keySync:      keySync,
	}, nil
}

func workloadSocketAddr(path string) string {
	return "unix://" + strings.TrimPrefix(path, "unix://")
}

// Start waits for the initial Workload API bundle when using workload_api keys.
func (v *Validator) Start(ctx context.Context) error {
	if v.keySync != nil {
		return v.keySync.Start(ctx)
	}
	return nil
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

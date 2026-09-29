// Package github provides a GitHub Actions OIDC token validator built on
// the generic jwt.Validator. It adds GitHub-specific allowlist checks
// and SPIRE selector generation.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtvalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/spiffetls"
	"go.yaml.in/yaml/v3"
)

const (
	DefaultIssuer = "https://token.actions.githubusercontent.com"

	// discoveryTimeout bounds discovery and JWKS fetches made over the SPIFFE
	// trust-bundle client.
	discoveryTimeout = 10 * time.Second
)

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
	return &Config{}, nil
}

// Config holds configuration for the GitHub OIDC validator.
type Config struct {
	IssuerURL string `yaml:"issuerURL"`
	// DiscoveryURL is the base URL used for OIDC discovery of the JWKS endpoint.
	// If empty, it defaults to IssuerURL. Set it when the issuer identifier is
	// not reachable at the address that serves the discovery document.
	DiscoveryURL string `yaml:"discoveryURL"`
	// DiscoverySPIFFEID, when set, validates the discovery endpoint's TLS
	// against the SPIFFE trust bundle and requires it to present exactly this
	// SPIFFE ID.
	//
	// Note that SPIFFE TLS does not verify the DNS name, so the host in
	// DiscoveryURL is an address and this is the identity.
	DiscoverySPIFFEID string `yaml:"discoverySPIFFEID"`
	// AgentWorkloadSocketPath is the UDS path for reaching the SPIFFE Workload
	// API. Defaults to the server-level spire.agentWorkloadSocketPath.
	AgentWorkloadSocketPath string `yaml:"agentWorkloadSocketPath"`
	// defaultWorkloadAPISocketPath is supplied by the config loader from the
	// server-level setting; see SetDefaultWorkloadAPISocketPath.
	defaultWorkloadAPISocketPath string   `yaml:"-"`
	Audiences                    []string `yaml:"audiences"`
	AllowedRepositoryOwners      []string `yaml:"allowedRepositoryOwners"`
	AllowedRepositories          []string `yaml:"allowedRepositories"`
	// KeyProvider allows injecting a custom key provider (e.g., one with
	// background refresh and fail-closed semantics). If nil, a default
	// on-demand JWKS fetching provider is used.
	KeyProvider validator.KeyProvider `yaml:"-"`
	// AllowHTTP permits http:// issuer URLs for local testing (e.g., mock OIDC servers).
	// Must not be enabled in production.
	AllowHTTP bool `yaml:"-"`
	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics `yaml:"-"`
}

func (c *Config) Unmarshal(raw *yaml.Node) error {
	return raw.Decode(c)
}

func (c *Config) ValidateConfig() error {
	if c.IssuerURL == "" {
		c.IssuerURL = DefaultIssuer
	}
	if c.DiscoveryURL == "" {
		// The issuer doubles as the discovery URL, so it will be fetched and
		// inherits the scheme requirement.
		if err := jwtvalidator.ValidateIssuerURL(c.IssuerURL, c.AllowHTTP); err != nil {
			return err
		}
	} else {
		// The issuer is only compared against the `iss` claim; the discovery URL
		// is the one dereferenced.
		if err := jwtvalidator.ValidateIssuerFormat(c.IssuerURL); err != nil {
			return err
		}
		if err := jwtvalidator.ValidateIssuerURL(c.DiscoveryURL, c.AllowHTTP); err != nil {
			return fmt.Errorf("invalid discovery URL: %w", err)
		}
	}
	if len(c.Audiences) == 0 {
		return errors.New("at least one audience must be specified")
	}
	if len(c.AllowedRepositories) == 0 && len(c.AllowedRepositoryOwners) == 0 {
		return errors.New("at least one of allowedRepositories or allowedRepositoryOwners must be specified")
	}
	if err := spiffetls.ValidateDiscoverySPIFFEID(c.DiscoverySPIFFEID); err != nil {
		return err
	}
	if c.DiscoverySPIFFEID != "" && c.workloadAPISocketPath() == "" {
		return errors.New("a workload API socket path must be available when discoverySPIFFEID is set; " +
			"set agentWorkloadSocketPath on the plugin or spire.agentWorkloadSocketPath on the server")
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

func (c *Config) NewValidator() (validator.TokenValidatorAndSelectorGenerator, error) {
	return NewValidator(*c)
}

func NewValidatorConfigFromJson(rawConfig json.RawMessage) (*Validator, error) {
	var cfg Config
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return nil, fmt.Errorf("github validator config error: %w", err)
	}
	return NewValidator(cfg)
}

// Validator validates GitHub Actions OIDC tokens.
// It implements validator.TokenValidator and validator.SelectorGenerator.
type Validator struct {
	jwtValidator            *jwtvalidator.Validator
	allowedRepositoryOwners []string
	allowedRepositories     []string
}

// NewValidator creates a new GitHub OIDC validator.
func NewValidator(cfg Config) (*Validator, error) {
	issuer := cfg.IssuerURL
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if len(cfg.AllowedRepositories) == 0 && len(cfg.AllowedRepositoryOwners) == 0 {
		return nil, fmt.Errorf("at least one of allowed_repositories or allowed_repository_owners must be configured")
	}

	// When a discovery SPIFFE ID is configured, supply an HTTP client whose TLS
	// is verified against the SPIFFE trust bundle. jwtvalidator uses it for both
	// the discovery document and the JWKS fetches that follow.
	var httpClient *http.Client
	if cfg.DiscoverySPIFFEID != "" {
		authorizer, err := spiffetls.AuthorizerFor(cfg.DiscoverySPIFFEID, "")
		if err != nil {
			return nil, err
		}
		httpClient, err = spiffetls.NewTrustBundleHTTPClient(cfg.workloadAPISocketPath(), authorizer, discoveryTimeout)
		if err != nil {
			return nil, err
		}
	}

	// DiscoveryURL is passed through as-is; jwtvalidator.NewValidator defaults it
	// to the issuer when empty.
	jv, err := jwtvalidator.NewValidator(jwtvalidator.Config{
		IssuerURL:    issuer,
		DiscoveryURL: cfg.DiscoveryURL,
		Audiences:    cfg.Audiences,
		KeyProvider:  cfg.KeyProvider,
		HTTPClient:   httpClient,
		AllowHTTP:    cfg.AllowHTTP,
		Metrics:      cfg.Metrics,
	})
	if err != nil {
		return nil, err
	}

	return &Validator{
		jwtValidator:            jv,
		allowedRepositoryOwners: cfg.AllowedRepositoryOwners,
		allowedRepositories:     cfg.AllowedRepositories,
	}, nil
}

// Validate validates a GitHub Actions OIDC token and returns claims.
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

// checkAllowLists enforces AND logic: when both lists are configured,
// the token must match both owner and repository.
func (v *Validator) checkAllowLists(raw map[string]interface{}) error {
	if len(v.allowedRepositoryOwners) > 0 {
		owner, _ := raw["repository_owner"].(string)
		if !validator.IsValueAllowed(owner, v.allowedRepositoryOwners) {
			return fmt.Errorf("repository owner %q is not in the allowed list", owner)
		}
	}
	if len(v.allowedRepositories) > 0 {
		repo, _ := raw["repository"].(string)
		if !validator.IsValueAllowed(repo, v.allowedRepositories) {
			return fmt.Errorf("repository %q is not in the allowed list", repo)
		}
	}
	return nil
}


package gitlab

import (
	"context"
	"errors"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtvalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/spiffetls"
	"go.yaml.in/yaml/v3"
)

const (
	DefaultIssuer = "https://gitlab.com"

	// discoveryTimeout bounds discovery and JWKS fetches made over the SPIFFE
	// trust-bundle client.
	discoveryTimeout = 10 * time.Second
)

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
	return &Config{}, nil
}

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
	defaultWorkloadAPISocketPath string                `yaml:"-"`
	Audiences                    []string              `yaml:"audiences"`
	AllowedProjectPaths   []string              `yaml:"allowedProjectPaths"`
	AllowedNamespacePaths []string              `yaml:"allowedNamespacePaths"`
	KeyProvider           validator.KeyProvider `yaml:"-"`
	AllowHTTP             bool                  `yaml:"-"`
	Metrics               validator.Metrics     `yaml:"-"`
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
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
	} else {
		// The issuer is only compared against the `iss` claim; the discovery URL
		// is the one dereferenced.
		if err := jwtvalidator.ValidateIssuerFormat(c.IssuerURL); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
		if err := jwtvalidator.ValidateIssuerURL(c.DiscoveryURL, c.AllowHTTP); err != nil {
			return fmt.Errorf("invalid discovery URL: %w", err)
		}
	}
	if len(c.Audiences) == 0 {
		return errors.New("at least one audience must be specified")
	}
	if len(c.AllowedProjectPaths) == 0 && len(c.AllowedNamespacePaths) == 0 {
		return errors.New("at least one of allowedProjectPaths or allowedNamespacePaths must be specified")
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
		return nil, fmt.Errorf("gitlab validator config error: %w", err)
	}
	return NewValidator(cfg)
}

type Validator struct {
	jwtValidator          *jwtvalidator.Validator
	allowedProjectPaths   []string
	allowedNamespacePaths []string
}

func NewValidator(cfg Config) (*Validator, error) {
	issuer := cfg.IssuerURL
	if issuer == "" {
		issuer = DefaultIssuer
	}
	if len(cfg.AllowedProjectPaths) == 0 && len(cfg.AllowedNamespacePaths) == 0 {
		return nil, fmt.Errorf("at least one of allowed_project_paths or allowed_namespace_paths must be configured")
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
		jwtValidator:          jv,
		allowedProjectPaths:   cfg.AllowedProjectPaths,
		allowedNamespacePaths: cfg.AllowedNamespacePaths,
	}, nil
}

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

func (v *Validator) checkAllowLists(raw map[string]interface{}) error {
	if len(v.allowedProjectPaths) > 0 {
		projectPath, _ := raw["project_path"].(string)
		if !validator.IsValueAllowed(projectPath, v.allowedProjectPaths) {
			return fmt.Errorf("project path %q is not in the allowed list", projectPath)
		}
	}
	if len(v.allowedNamespacePaths) > 0 {
		namespacePath, _ := raw["namespace_path"].(string)
		if !validator.IsValueAllowed(namespacePath, v.allowedNamespacePaths) {
			return fmt.Errorf("namespace path %q is not in the allowed list", namespacePath)
		}
	}
	return nil
}

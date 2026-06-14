package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/registry"
)

// Duration is a time.Duration that unmarshals from JSON as either a duration
// string (e.g. "1h", "10m") or an integer number of nanoseconds.
type Duration time.Duration

var pluginNamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,6})?$`)

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(dur)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(n)
	return nil
}

type SpireIdentityExchangeConfig struct {
	Name        string           `json:"name"`
	LogLevel    string           `json:"logLevel"`
	PurposeMode string           `json:"purposeMode"`
	Server      ServerConfig     `json:"server"`
	SPIRE       SPIREConfig      `json:"spire"`
	Auth        AuthConfig       `json:"auth"`
	GitHubOIDC  GitHubOIDCConfig `json:"githubOIDC"`
	K8sSAToken  K8sSATokenConfig `json:"k8sSAToken"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Port        int       `json:"port"`
	MetricsPort int       `json:"metricsPort"`
	RestPort    int       `json:"restPort"`
	TLS         TLSConfig `json:"tls"`
}

// TLSConfig contains TLS configuration
type TLSConfig struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// AuthConfig contains Authentication configuration
type AuthConfig struct {
	Plugins       []PluginConfig                                          `json:"plugins"`
	LoadedPlugins map[string]validator.TokenValidatorAndSelectorGenerator `json:"-"`
	LoadedStacks  map[string]validator.TokenValidatorAndSelectorGenerator `json:"-"`
}

// PluginConfig is the operator config for one plugin. SPIFFE ID and TTL are not
// set here — both surfaces use SPIRE's Delegated Identity API, which resolves
// both from the registration entry matching the plugin's generated selectors.
type PluginConfig struct {
	Name      string                         `json:"name"`
	Plugin    string                         `json:"plugin"`
	RawConfig json.RawMessage                `json:"config"`
	Config    validator.TokenValidatorLoader `json:"-"`
}

// SPIREConfig contains SPIRE server configurations
type SPIREConfig struct {
	// Unix domain socket path for SPIRE Server API
	UnixSocketPath string `json:"unixSocketPath"`

	// Unix domain socket path for SPIRE Agent Workload API.
	// Used by the REST trust-bundle endpoint to stream bundle updates.
	AgentWorkloadSocketPath string `json:"agentWorkloadSocketPath"`

	// Unix domain socket path for SPIRE Agent Delegated Identity API.
	// When set, the REST /api/v1/svid/{stack}/x509 endpoint issues SVIDs by fetching
	// them through this socket rather than calling SPIRE Server directly. The
	// agent listening on this socket must include this exchange's SPIFFE ID in
	// its authorized_delegates configuration.
	AgentDelegatedSocketPath string `json:"agentDelegatedSocketPath"`

	// Trust domain
	TrustDomain string `json:"trustDomain"`

	// SVID TTL
	SVIDTTL Duration `json:"svidTTL"`
}

// GitHubOIDCConfig contains GitHub Actions OIDC validator configuration
type GitHubOIDCConfig struct {
	// Whether this validator is enabled
	Enabled bool `json:"enabled"`

	// OIDC issuer URL e.g., https://token.actions.githubusercontent.com
	Issuer string `json:"issuer"`

	// Expected audience
	Audiences []string `json:"audiences"`

	// JWKS endpoint (optional, will be discovered from issuer)
	JWKSURI string `json:"jwksUri"`

	// SPIFFE ID template using Go template syntax
	// e.g. "spiffe://example.org/github/{{.org}}/{{.repository}}"
	SPIFFEIDTemplate string `json:"spiffeIdTemplate"`

	// Example:
	// 1. "example-org/*" would allow all repositories in the example-org organization.
	// 2. "example-org/repo1,example-org/repo2" would allow only the specified repositories.
	// 3. "*" would allow all repositories.
	AllowedRepositories []string `json:"allowedRepositories"`

	// Optional: Required claims. Note that audience should not be specified in required claims
	RequiredClaims []string `json:"requiredClaims"`

	// WorkflowTTLOverrides maps a job_workflow_ref value to an SVID TTL.
	// When the GitHub OIDC token's job_workflow_ref claim exactly matches a key,
	// the corresponding TTL is used instead of the default svidTTL.
	WorkflowTTLOverrides map[string]Duration `json:"workflowTTLOverrides"`

	// Skip time-based claim validation (exp, nbf, iat). If true, expired tokens will be accepted.
	SkipTokenExpiration bool `json:"skipTokenExpiration"`

	// Cache configuration for JWKS
	JWKSCacheDuration Duration `json:"jwksCacheDuration"`

	// SVID TTL for certificates issued via this auth method.
	// Overrides spire.svidTTL when set. Falls back to spire.svidTTL if zero.
	SVIDTTL Duration `json:"svidTTL"`
}

// K8sSATokenConfig contains Kubernetes service account token validator configuration
type K8sSATokenConfig struct {
	// Whether this validator is enabled
	Enabled bool `json:"enabled"`

	// Optional. Operator-defined cluster identifier exposed to the SPIFFE ID template
	// as {{.k8s_cluster_name}}. This MUST come from configuration — never from the
	// request — because each Validator authenticates against exactly one cluster
	// (the one its kubeconfig / in-cluster credentials target) and accepting a
	// caller-supplied value would allow cross-cluster identity impersonation.
	ClusterName string `json:"clusterName"`

	// Optional. Expected audiences for incoming service-account tokens. When set,
	// these are passed in the TokenReview Spec.Audiences and the response's status
	// audiences must intersect with this list. Strongly recommended: configure a
	// dedicated audience (e.g. "spire-identity-exchange") for tokens minted for
	// this service so tokens issued for other recipients cannot be replayed.
	Audiences []string `json:"audiences"`

	// SPIFFE ID template using Go template syntax
	// Available variables are raw JWT claims, e.g. "spiffe://example.org/k8s/{{.sub}}"
	SPIFFEIDTemplate string `json:"spiffeIdTemplate"`

	// Optional path to a kubeconfig file used to reach the Kubernetes API
	// server for TokenReview calls.
	//
	// Resolution order (independent of this field): the runtime always probes
	// in-cluster credentials first — when SIE runs as a pod, the kubelet-injected
	// ServiceAccount token wins outright and this field is ignored. Only when
	// SIE is NOT running in-cluster does kubeconfig loading happen, and only
	// then does this field matter: when set, it is the single file loaded;
	// when empty, the loader falls back to $KUBECONFIG, then $HOME/.kube/config.
	//
	// A kubeconfig file natively expresses every K8s auth flavor (in-cluster
	// SA token, mTLS, bearer token, AWS IAM / GKE / Azure exec plugins,
	// SPIRE-issued SVID via exec plugin), so this single field replaces what
	// would otherwise be apiHost + caFile + certFile + keyFile.
	Kubeconfig string `json:"kubeconfig"`

	// SVID TTL for certificates issued via this auth method.
	// Overrides spire.svidTTL when set. Falls back to spire.svidTTL if zero.
	SVIDTTL Duration `json:"svidTTL"`
}

func (c *AuthConfig) Validate() error {
	usedPlugins := make(map[string]struct{})
	var errs []error
	for i, plugin := range c.Plugins {
		if c.Plugins[i].Name == "" {
			plugin.Name = plugin.Plugin
			c.Plugins[i].Name = plugin.Plugin
		}
		if _, exists := usedPlugins[plugin.Name]; exists {
			errs = append(errs, fmt.Errorf("plugin name %s is defined more than once", plugin.Name))
			continue
		}
		if !pluginNamePattern.MatchString(plugin.Name) {
			errs = append(errs, fmt.Errorf("Plugin name %s is invalid", plugin.Name))
			continue
		}
		pluginGenerator, exists := registry.AllBuiltinPlugins[plugin.Plugin]
		if !exists {
			errs = append(errs, fmt.Errorf("plugin type %q is unknown", plugin.Plugin))
		} else {
			config, err := pluginGenerator()
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to initialize plugin %q: %w", plugin.Name, err))
			} else if err := config.Unmarshal(plugin.RawConfig); err != nil {
				errs = append(errs, fmt.Errorf("failed to unmarshal config for plugin %q: %w", plugin.Name, err))
			} else if err := config.ValidateConfig(); err != nil {
				errs = append(errs, fmt.Errorf("invalid config for plugin %q: %w", plugin.Name, err))
			} else {
				c.Plugins[i].Config = config
			}
		}
		usedPlugins[plugin.Name] = struct{}{}
	}
	return errors.Join(errs...)
}

func (c *ServerConfig) Validate() error {
	var errs []error

	if c.MetricsPort == 0 {
		errs = append(errs, errors.New("server.metricsPort is required"))
	}

	if c.TLS.CertFile == "" {
		errs = append(errs, errors.New("server.tls.certFile path is required"))
	} else if _, err := os.Stat(c.TLS.CertFile); err != nil {
		errs = append(errs, fmt.Errorf("server.tls.certFile not found at %q: %w", c.TLS.CertFile, err))
	}

	if c.TLS.KeyFile == "" {
		errs = append(errs, errors.New("server.tls.keyFile path is required"))
	} else if _, err := os.Stat(c.TLS.KeyFile); err != nil {
		errs = append(errs, fmt.Errorf("server.tls.keyFile not found at %q: %w", c.TLS.KeyFile, err))
	}

	return errors.Join(errs...)
}

func (c *SPIREConfig) Validate() error {
	var errs []error

	if c.TrustDomain == "" {
		errs = append(errs, errors.New("spire.trustDomain is required"))
	}

	return errors.Join(errs...)
}

func (c *GitHubOIDCConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.Issuer == "" {
		errs = append(errs, errors.New("githubOIDC.issuer is required when githubOIDC is enabled"))
	}
	if len(c.Audiences) == 0 {
		errs = append(errs, errors.New("githubOIDC.audiences is required when githubOIDC is enabled"))
	}
	if c.SPIFFEIDTemplate == "" {
		errs = append(errs, errors.New("githubOIDC.spiffeIdTemplate is required when githubOIDC is enabled"))
	}
	if len(c.AllowedRepositories) == 0 {
		errs = append(errs, errors.New("githubOIDC.allowedRepositories is required when githubOIDC is enabled"))
	}
	// 0 means "use default"; anything else must be a sane positive duration. The
	// JWKS refresher uses time.NewTicker(ttl/2), which panics on non-positive values.
	const minJWKSCacheDuration = time.Second
	if d := time.Duration(c.JWKSCacheDuration); d != 0 && d < minJWKSCacheDuration {
		errs = append(errs, fmt.Errorf("githubOIDC.jwksCacheDuration must be 0 (use default) or >= %s, got %s", minJWKSCacheDuration, d))
	}
	return errors.Join(errs...)
}

func (c *K8sSATokenConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.SPIFFEIDTemplate == "" {
		errs = append(errs, errors.New("k8sSAToken.spiffeIdTemplate is required when k8sSAToken is enabled"))
	}
	// API server connectivity comes from the kubeconfig / in-cluster fallback
	// resolved at runtime in pkg/validator/k8s. Only check that an explicit
	// kubeconfig path, when set, points at an existing file; absence is fine
	// because the resolver will fall back to in-cluster credentials, then
	// $KUBECONFIG, then $HOME/.kube/config.
	if c.Kubeconfig != "" {
		if _, err := os.Stat(c.Kubeconfig); err != nil {
			errs = append(errs, fmt.Errorf("k8sSAToken.kubeconfig not found at %q: %w", c.Kubeconfig, err))
		}
	}
	return errors.Join(errs...)
}

// Validate validates the configuration
func (c *SpireIdentityExchangeConfig) Validate() error {
	var errs []error

	if c.LogLevel != "" {
		switch c.LogLevel {
		case "debug", "info", "warn", "error", "dpanic", "panic", "fatal":
		default:
			errs = append(errs, fmt.Errorf("logLevel %q is not a recognized level (debug|info|warn|error|dpanic|panic|fatal)", c.LogLevel))
		}
	}

	if c.PurposeMode != "" {
		switch c.PurposeMode {
		case string(validator.PurposeModePurpose), string(validator.PurposeModeShared):
		default:
			errs = append(errs, fmt.Errorf("purposeMode %q is not recognized (purpose|shared)", c.PurposeMode))
		}
	}

	errs = append(errs, c.Auth.Validate())
	errs = append(errs, c.Server.Validate())
	errs = append(errs, c.SPIRE.Validate())
	errs = append(errs, c.GitHubOIDC.Validate())
	errs = append(errs, c.K8sSAToken.Validate())

	if c.Server.RestPort != 0 && c.SPIRE.AgentWorkloadSocketPath == "" {
		errs = append(errs, errors.New("spire.agentWorkloadSocketPath is required when server.restPort is enabled"))
	}
	if c.Server.RestPort != 0 && c.SPIRE.AgentDelegatedSocketPath == "" {
		errs = append(errs, errors.New("spire.agentDelegatedSocketPath is required when server.restPort is enabled"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

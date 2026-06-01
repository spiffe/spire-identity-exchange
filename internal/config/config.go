package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Duration is a time.Duration that unmarshals from JSON as either a duration
// string (e.g. "1h", "10m") or an integer number of nanoseconds.
type Duration time.Duration

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
	Name       string           `json:"name"`
	LogLevel   string           `json:"logLevel"`
	Server     ServerConfig     `json:"server"`
	SPIRE      SPIREConfig      `json:"spire"`
	GitHubOIDC GitHubOIDCConfig `json:"githubOIDC"`
	K8sSAToken K8sSATokenConfig `json:"k8sSAToken"`
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

// SPIREConfig contains SPIRE server configurations
type SPIREConfig struct {
	// Unix domain socket path for SPIRE Server API
	UnixSocketPath string `json:"unixSocketPath"`

	// Unix domain socket path for SPIRE Agent Workload API
	AgentWorkloadSocketPath string `json:"agentWorkloadSocketPath"`

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

	// Required. Kubernetes API server URL used for the TokenReview call.
	// Must be a trusted, operator-configured value; the token's iss claim is NEVER
	// used as a network destination because it is attacker-controlled until the
	// token has been verified.
	APIHost string `json:"apiHost"`

	// Optional. Operator-defined cluster identifier exposed to the SPIFFE ID template
	// as {{.k8s_cluster_name}}. This MUST come from configuration — never from the
	// request — because each Validator authenticates against exactly one cluster
	// (apiHost) and accepting a caller-supplied value would allow cross-cluster
	// identity impersonation.
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

	// TLS configuration for authenticating with the Kubernetes API server
	TLS K8sAPIClientTlsConfig `json:"tls"`

	// SVID TTL for certificates issued via this auth method.
	// Overrides spire.svidTTL when set. Falls back to spire.svidTTL if zero.
	SVIDTTL Duration `json:"svidTTL"`
}

// K8sAPIClientTlsConfig contains Kubernetes API server configuration for mutual TLS with k8s API server.
type K8sAPIClientTlsConfig struct {
	// CA certificate file used to verify the K8s API server certificate
	CAFile string `json:"caFile"`

	// Client certificate presented to authenticate with the k8s API server
	CertFile string `json:"certFile"`

	// Client key presented to authenticate with the k8s API server
	KeyFile string `json:"keyFile"`
}

func (c *ServerConfig) Validate() error {
	var errs []error

	if c.Port == 0 {
		errs = append(errs, errors.New("server.port is required"))
	}

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

	if c.UnixSocketPath == "" {
		errs = append(errs, errors.New("spire.unixSocketPath is required"))
	}
	if c.TrustDomain == "" {
		errs = append(errs, errors.New("spire.trustDomain is required"))
	}

	return errors.Join(errs...)
}

func (c *K8sAPIClientTlsConfig) Validate() error {
	var errs []error

	if c.CAFile == "" {
		errs = append(errs, errors.New("tls.caFile is required"))
	} else if _, err := os.Stat(c.CAFile); err != nil {
		errs = append(errs, fmt.Errorf("tls.caFile not found at %q: %w", c.CAFile, err))
	}

	if c.CertFile == "" {
		errs = append(errs, errors.New("tls.certFile is required"))
	} else if _, err := os.Stat(c.CertFile); err != nil {
		errs = append(errs, fmt.Errorf("tls.certFile not found at %q: %w", c.CertFile, err))
	}

	if c.KeyFile == "" {
		errs = append(errs, errors.New("tls.keyFile is required"))
	} else if _, err := os.Stat(c.KeyFile); err != nil {
		errs = append(errs, fmt.Errorf("tls.keyFile not found at %q: %w", c.KeyFile, err))
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
	if c.APIHost == "" {
		errs = append(errs, errors.New("k8sSAToken.apiHost is required when k8sSAToken is enabled"))
	} else {
		// TokenReview sends the caller's bearer token; require TLS to prevent
		// cleartext credential exposure to a misconfigured plain-HTTP endpoint.
		u, err := url.Parse(c.APIHost)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("k8sSAToken.apiHost %q is not a valid URL: %w", c.APIHost, err))
		case u.Scheme != "https":
			errs = append(errs, fmt.Errorf("k8sSAToken.apiHost must use https:// (got %q)", c.APIHost))
		}
	}
	if c.SPIFFEIDTemplate == "" {
		errs = append(errs, errors.New("k8sSAToken.spiffeIdTemplate is required when k8sSAToken is enabled"))
	}
	errs = append(errs, c.TLS.Validate())
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

	errs = append(errs, c.Server.Validate())
	errs = append(errs, c.SPIRE.Validate())
	errs = append(errs, c.GitHubOIDC.Validate())
	errs = append(errs, c.K8sSAToken.Validate())

	if c.Server.RestPort != 0 && c.SPIRE.AgentWorkloadSocketPath == "" {
		errs = append(errs, errors.New("spire.agentWorkloadSocketPath is required when server.restPort is enabled"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

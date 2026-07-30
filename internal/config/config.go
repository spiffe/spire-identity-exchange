package config

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/registry"
	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration that unmarshals from JSON as either a duration
// string (e.g. "1h", "10m") or an integer number of nanoseconds.
type Duration time.Duration

var PluginNamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,6})?$`)

func (d *Duration) UnmarshalYAML(b *yaml.Node) error {
	var s string
	if err := b.Decode(&s); err == nil {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(dur)
		return nil
	}
	var n int64
	if err := b.Decode(&n); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(n)
	return nil
}

type SpireIdentityExchangeConfig struct {
	Name        string           `yaml:"name"`
	LogLevel    string           `yaml:"logLevel"`
	PurposeMode string           `yaml:"purposeMode"`
	Server      ServerConfig     `yaml:"server"`
	SPIRE       SPIREConfig      `yaml:"spire"`
	Auth        AuthConfig       `yaml:"auth"`
	GitHubOIDC  GitHubOIDCConfig `yaml:"githubOIDC"`
	K8sSAToken  K8sSATokenConfig `yaml:"k8sSAToken"`
}

// ServerConfig contains HTTP server configuration.
//
// Serving is a two-axis matrix: protocol (gRPC or REST) crossed with certificate
// source (a file on disk under tls, or this process's own X509-SVID under spiffe).
// All four listeners are independent and can run at once.
type ServerConfig struct {
	MetricsPort int                `yaml:"metricsPort"`
	TLS         TLSConfig          `yaml:"tls"`
	SPIFFE      SPIFFEServerConfig `yaml:"spiffe"`

	// Removed keys. Retained only so a config written against the old schema
	// fails with a message naming the replacement — yaml.Unmarshal ignores
	// unknown keys, so without these a stale config would start nothing and
	// report the generic "no listener enabled".
	GrpcPort int `yaml:"grpcPort"`
	RestPort int `yaml:"restPort"`
}

// ListenerConfig is one protocol surface on one certificate source.
type ListenerConfig struct {
	Enable bool `yaml:"enable"`
	Port   int  `yaml:"port"`
}

// Enabled reports whether this listener should be started. A zero port means
// disabled even when enable is true.
func (l ListenerConfig) Enabled() bool { return l.Enable && l.Port != 0 }

// TLSConfig configures the listeners served with a certificate loaded from disk.
type TLSConfig struct {
	CertFile string         `yaml:"certFile"`
	KeyFile  string         `yaml:"keyFile"`
	GRPC     ListenerConfig `yaml:"grpc"`
	REST     ListenerConfig `yaml:"rest"`
}

// SPIFFEServerConfig mirrors TLSConfig minus the cert paths: these listeners are
// served with this process's own X509-SVID, fetched from the SPIRE Agent Workload
// API at spire.agentWorkloadSocketPath. Client authentication is unchanged from
// the tls listeners — callers still present a bearer token.
type SPIFFEServerConfig struct {
	GRPC ListenerConfig `yaml:"grpc"`
	REST ListenerConfig `yaml:"rest"`
}

// FileTLSEnabled reports whether any listener needs the on-disk certificate.
func (c *ServerConfig) FileTLSEnabled() bool { return c.TLS.GRPC.Enabled() || c.TLS.REST.Enabled() }

// SPIFFEEnabled reports whether any listener needs a server X509-SVID.
func (c *ServerConfig) SPIFFEEnabled() bool {
	return c.SPIFFE.GRPC.Enabled() || c.SPIFFE.REST.Enabled()
}

// AnyGRPCEnabled reports whether any gRPC listener is enabled, on either
// certificate source.
func (c *ServerConfig) AnyGRPCEnabled() bool { return c.TLS.GRPC.Enabled() || c.SPIFFE.GRPC.Enabled() }

// AnyRESTEnabled reports whether any REST listener is enabled, on either
// certificate source.
func (c *ServerConfig) AnyRESTEnabled() bool { return c.TLS.REST.Enabled() || c.SPIFFE.REST.Enabled() }

// AnyEnabled reports whether there is anything at all to serve.
func (c *ServerConfig) AnyEnabled() bool { return c.FileTLSEnabled() || c.SPIFFEEnabled() }

// NamedListeners returns every listener paired with its config key, enabled or
// not, in a stable order. Callers filter on ListenerConfig.Enabled().
func (c *ServerConfig) NamedListeners() []NamedListener {
	return []NamedListener{
		{Name: "server.tls.grpc", Config: c.TLS.GRPC},
		{Name: "server.tls.rest", Config: c.TLS.REST},
		{Name: "server.spiffe.grpc", Config: c.SPIFFE.GRPC},
		{Name: "server.spiffe.rest", Config: c.SPIFFE.REST},
	}
}

// NamedListener is a listener config alongside the config key it came from, so
// validation and startup logging can name the offending listener.
type NamedListener struct {
	Name   string
	Config ListenerConfig
}

// AuthConfig contains Authentication configuration
type AuthConfig struct {
	Plugins            PluginConfigs                                      `yaml:"plugins"`
	Stacks             StackConfigs                                       `yaml:"stacks"`
	PassthroughPlugins *bool                                              `yaml:"passthroughPlugins"`
	LoadedPlugins map[string]validator.TokenValidatorAndSelectorGenerator `yaml:"-"`
	LoadedStacks  map[string]validator.TokenValidatorAndSelectorGenerator `yaml:"-"`
}

// PluginConfigs maps plugin name to its config. Both sections are mappings
// rather than lists so that a Helm values override can patch one entry instead
// of replacing the whole block — YAML lists do not merge.
type PluginConfigs map[string]PluginConfig

// StackConfigs maps stack name to its config.
type StackConfigs map[string]StackConfig

// PluginConfig is the operator config for one plugin. The plugin's name is the
// key it appears under in PluginConfigs, and is also the default value of
// Plugin. SPIFFE ID and TTL are not set here — both surfaces use SPIRE's
// Delegated Identity API, which resolves both from the registration entry
// matching the plugin's generated selectors.
type PluginConfig struct {
	Plugin    string                         `yaml:"plugin"`
	Enabled   *bool                          `yaml:"enabled"`
	RawConfig yaml.Node                      `yaml:"config"`
	Config    validator.TokenValidatorLoader `yaml:"-"`
}

// StackConfig is the operator config for one stack. The stack's name is the key
// it appears under in StackConfigs.
type StackConfig struct {
	Plugins []string `yaml:"plugins"`
}

// UnmarshalYAML decodes the plugins mapping, naming the replacement when it
// finds the removed list form. yaml.Unmarshal would otherwise report only
// "cannot unmarshal !!seq into config.PluginConfigs".
func (p *PluginConfigs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return errors.New("auth.plugins is a mapping keyed by plugin name, not a list: " +
			"replace each `- name: foo` / `plugin: bar` entry with a `foo:` key holding `plugin: bar`, " +
			"omitting `plugin` where it matches the name")
	}
	// Named type so decoding does not recurse back into this method.
	type plugins map[string]PluginConfig
	var m plugins
	if err := node.Decode(&m); err != nil {
		return err
	}
	*p = PluginConfigs(m)
	return nil
}

// UnmarshalYAML decodes the stacks mapping, naming the replacement when it
// finds the removed list form.
func (s *StackConfigs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		return errors.New("auth.stacks is a mapping keyed by stack name, not a list: " +
			"replace each `- name: foo` / `plugins: [...]` entry with a `foo:` key holding `plugins: [...]`")
	}
	// Named type so decoding does not recurse back into this method.
	type stacks map[string]StackConfig
	var m stacks
	if err := node.Decode(&m); err != nil {
		return err
	}
	*s = StackConfigs(m)
	return nil
}

// SPIREConfig contains SPIRE server configurations
type SPIREConfig struct {
	// Unix domain socket path for SPIRE Server API
	UnixSocketPath string `yaml:"unixSocketPath"`

	// Unix domain socket path for SPIRE Agent Workload API.
	// Used by the REST trust-bundle endpoint to stream bundle updates.
	AgentWorkloadSocketPath string `yaml:"agentWorkloadSocketPath"`

	// Unix domain socket path for SPIRE Agent Delegated Identity API.
	// When set, the REST /api/v1/svid/{stack}/x509 endpoint issues SVIDs by fetching
	// them through this socket rather than calling SPIRE Server directly. The
	// agent listening on this socket must include this exchange's SPIFFE ID in
	// its authorized_delegates configuration.
	AgentDelegatedSocketPath string `yaml:"agentDelegatedSocketPath"`

	// Trust domain
	TrustDomain string `yaml:"trustDomain"`

	// SVID TTL
	SVIDTTL Duration `yaml:"svidTTL"`
}

// GitHubOIDCConfig contains GitHub Actions OIDC validator configuration
type GitHubOIDCConfig struct {
	// Whether this validator is enabled
	Enabled bool `yaml:"enabled"`

	// OIDC issuer URL e.g., https://token.actions.githubusercontent.com
	Issuer string `yaml:"issuer"`

	// Expected audience
	Audiences []string `yaml:"audiences"`

	// JWKS endpoint (optional, will be discovered from issuer)
	JWKSURI string `yaml:"jwksUri"`

	// SPIFFE ID template using Go template syntax
	// e.g. "spiffe://example.org/github/{{.org}}/{{.repository}}"
	SPIFFEIDTemplate string `yaml:"spiffeIdTemplate"`

	// Example:
	// 1. "example-org/*" would allow all repositories in the example-org organization.
	// 2. "example-org/repo1,example-org/repo2" would allow only the specified repositories.
	// 3. "*" would allow all repositories.
	AllowedRepositories []string `yaml:"allowedRepositories"`

	// Optional: Required claims. Note that audience should not be specified in required claims
	RequiredClaims []string `yaml:"requiredClaims"`

	// WorkflowTTLOverrides maps a job_workflow_ref value to an SVID TTL.
	// When the GitHub OIDC token's job_workflow_ref claim exactly matches a key,
	// the corresponding TTL is used instead of the default svidTTL.
	WorkflowTTLOverrides map[string]Duration `yaml:"workflowTTLOverrides"`

	// Skip time-based claim validation (exp, nbf, iat). If true, expired tokens will be accepted.
	SkipTokenExpiration bool `yaml:"skipTokenExpiration"`

	// Cache configuration for JWKS
	JWKSCacheDuration Duration `yaml:"jwksCacheDuration"`

	// SVID TTL for certificates issued via this auth method.
	// Overrides spire.svidTTL when set. Falls back to spire.svidTTL if zero.
	SVIDTTL Duration `yaml:"svidTTL"`
}

// K8sSATokenConfig contains Kubernetes service account token validator configuration
type K8sSATokenConfig struct {
	// Whether this validator is enabled
	Enabled bool `yaml:"enabled"`

	// Optional. Operator-defined cluster identifier exposed to the SPIFFE ID template
	// as {{.k8s_cluster_name}}. This MUST come from configuration — never from the
	// request — because each Validator authenticates against exactly one cluster
	// (the one its kubeconfig / in-cluster credentials target) and accepting a
	// caller-supplied value would allow cross-cluster identity impersonation.
	ClusterName string `yaml:"clusterName"`

	// Optional. Expected audiences for incoming service-account tokens. When set,
	// these are passed in the TokenReview Spec.Audiences and the response's status
	// audiences must intersect with this list. Strongly recommended: configure a
	// dedicated audience (e.g. "spire-identity-exchange") for tokens minted for
	// this service so tokens issued for other recipients cannot be replayed.
	Audiences []string `yaml:"audiences"`

	// SPIFFE ID template using Go template syntax
	// Available variables are raw JWT claims, e.g. "spiffe://example.org/k8s/{{.sub}}"
	SPIFFEIDTemplate string `yaml:"spiffeIdTemplate"`

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
	Kubeconfig string `yaml:"kubeconfig"`

	// SVID TTL for certificates issued via this auth method.
	// Overrides spire.svidTTL when set. Falls back to spire.svidTTL if zero.
	SVIDTTL Duration `yaml:"svidTTL"`
}

func (c *AuthConfig) Validate() error {
	passthroughPlugins := true
	if (c.PassthroughPlugins != nil && *c.PassthroughPlugins == false) {
		passthroughPlugins = false
	}
	// Names are map keys, so duplicates are impossible; the maps are walked in
	// sorted order only so the joined errors come out in a stable order.
	usedPlugins := make(map[string]struct{})
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(c.Plugins)) {
		plugin := c.Plugins[name]
		if plugin.Enabled != nil && !*plugin.Enabled {
			continue
		}
		if !PluginNamePattern.MatchString(name) {
			errs = append(errs, fmt.Errorf("Plugin name %s is invalid", name))
			continue
		}
		// A plugin keyed by its own type needs no plugin field.
		if plugin.Plugin == "" {
			plugin.Plugin = name
			c.Plugins[name] = plugin
		}
		pluginGenerator, exists := registry.AllBuiltinPlugins[plugin.Plugin]
		if !exists {
			errs = append(errs, fmt.Errorf("plugin type %q is unknown", plugin.Plugin))
		} else {
			config, err := pluginGenerator()
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to initialize plugin %q: %w", name, err))
			} else if err := config.Unmarshal(&plugin.RawConfig); err != nil {
				errs = append(errs, fmt.Errorf("failed to unmarshal config for plugin %q: %w", name, err))
			} else if err := config.ValidateConfig(); err != nil {
				errs = append(errs, fmt.Errorf("invalid config for plugin %q: %w", name, err))
			} else {
				plugin.Config = config
				c.Plugins[name] = plugin
			}
		}
		usedPlugins[name] = struct{}{}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Stacks)) {
		if _, exists := usedPlugins[name]; passthroughPlugins && exists {
			errs = append(errs, fmt.Errorf("stack name %s is defined the same as an existing plugin", name))
			continue
		}
		if !PluginNamePattern.MatchString(name) {
			errs = append(errs, fmt.Errorf("Stack name %s is invalid", name))
		}
	}
	return errors.Join(errs...)
}

const maxPort = 65535

func (c *ServerConfig) Validate() error {
	var errs []error

	if c.MetricsPort == 0 {
		errs = append(errs, errors.New("server.metricsPort is required"))
	}

	if c.GrpcPort != 0 {
		errs = append(errs, errors.New("server.grpcPort has been removed; use server.tls.grpc.{enable,port}"))
	}
	if c.RestPort != 0 {
		errs = append(errs, errors.New("server.restPort has been removed; use server.tls.rest.{enable,port}"))
	}

	// A zero port disables a listener, so it is never a collision candidate. Any
	// other out-of-range value is an operator mistake — never silently ignored,
	// because net.Listen would fail mid-startup with an opaque message.
	usedPorts := map[int]string{}
	if c.MetricsPort != 0 {
		usedPorts[c.MetricsPort] = "server.metricsPort"
	}
	for _, l := range c.NamedListeners() {
		if l.Config.Port < 0 || l.Config.Port > maxPort {
			errs = append(errs, fmt.Errorf("%s.port %d is out of range (1-%d, or 0 to disable)", l.Name, l.Config.Port, maxPort))
			continue
		}
		if !l.Config.Enabled() {
			continue
		}
		if prev, dup := usedPorts[l.Config.Port]; dup {
			errs = append(errs, fmt.Errorf("%s.port %d collides with %s", l.Name, l.Config.Port, prev))
			continue
		}
		usedPorts[l.Config.Port] = l.Name
	}

	// Only the file-sourced listeners need a certificate on disk. A SPIFFE-only
	// deployment legitimately has no certFile/keyFile at all.
	if c.FileTLSEnabled() {
		if c.TLS.CertFile == "" {
			errs = append(errs, errors.New("server.tls.certFile path is required when a server.tls listener is enabled"))
		} else if _, err := os.Stat(c.TLS.CertFile); err != nil {
			errs = append(errs, fmt.Errorf("server.tls.certFile not found at %q: %w", c.TLS.CertFile, err))
		}

		if c.TLS.KeyFile == "" {
			errs = append(errs, errors.New("server.tls.keyFile path is required when a server.tls listener is enabled"))
		} else if _, err := os.Stat(c.TLS.KeyFile); err != nil {
			errs = append(errs, fmt.Errorf("server.tls.keyFile not found at %q: %w", c.TLS.KeyFile, err))
		}
	}

	if !c.AnyEnabled() {
		errs = append(errs, errors.New("no listener enabled: set a nonzero port and enable on at least one of "+
			"server.tls.grpc, server.tls.rest, server.spiffe.grpc, server.spiffe.rest"))
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

	// The Workload API socket serves two distinct needs, so name the one that
	// actually triggered the requirement.
	if c.SPIRE.AgentWorkloadSocketPath == "" {
		switch {
		case c.Server.SPIFFEEnabled():
			errs = append(errs, errors.New("spire.agentWorkloadSocketPath is required when a server.spiffe listener is enabled; it is the source of the server's own X509-SVID"))
		case c.Server.AnyRESTEnabled():
			errs = append(errs, errors.New("spire.agentWorkloadSocketPath is required when a REST listener is enabled; it feeds the trust bundle cache"))
		}
	}
	if c.Server.AnyRESTEnabled() && c.SPIRE.AgentDelegatedSocketPath == "" {
		errs = append(errs, errors.New("spire.agentDelegatedSocketPath is required when a REST listener is enabled"))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

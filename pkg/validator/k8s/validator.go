// Package k8s provides a Kubernetes service-account token validator that
// authenticates tokens via the Kubernetes TokenReview API and/or an in-process
// JWKS signature check, and emits SPIRE selectors from the resulting claims. It
// implements validator.TokenValidator and validator.SelectorGenerator.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"go.yaml.in/yaml/v3"
)

// TokenValidatorLoaderGenerator returns a fresh Config that can be unmarshaled,
// validated, and used to construct a Validator. It is registered with the
// validator registry under the "k8s_psat" plugin name — matching SPIRE's
// node-attestor naming for projected SA tokens.
func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
	return &Config{}, nil
}

// Config holds configuration for the K8s SA token validator.
type Config struct {
	// ClusterName is an operator-defined cluster identifier exposed to the SPIFFE
	// ID template as {{.k8s_cluster_name}} and emitted as a selector. It MUST
	// come from configuration — never from the request — because each Validator
	// authenticates against exactly one cluster (the one its kubeconfig / in-cluster
	// credentials target) and accepting a caller-supplied value would allow
	// cross-cluster identity impersonation.
	ClusterName string `yaml:"clusterName"`

	// Audiences are forwarded to the TokenReview Spec.Audiences so Kubernetes
	// binds the authentication decision to the audiences this service expects.
	// Strongly recommended: configure a dedicated audience (e.g. "spire-identity-exchange").
	Audiences []string `yaml:"audiences"`

	// AllowedNamespaces restricts which Kubernetes namespaces may exchange a token.
	// Each entry is a bare namespace name with optional trailing wildcard
	// (e.g. "prod", "team-*"). At least one of AllowedNamespaces or
	// AllowedServiceAccounts must be set.
	AllowedNamespaces []string `yaml:"allowedNamespaces"`

	// AllowedServiceAccounts restricts which service accounts may exchange a token.
	// Each entry is "namespace/serviceAccountName" with optional trailing wildcard
	// (e.g. "prod/web", "team-*/runner"). At least one of AllowedNamespaces or
	// AllowedServiceAccounts must be set.
	AllowedServiceAccounts []string `yaml:"allowedServiceAccounts"`

	// Kubeconfig is an optional path to a kubeconfig file used to reach the
	// Kubernetes API server for TokenReview calls.
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
	// SPIRE-issued SVID via exec plugin), so a single field replaces what
	// would otherwise be apiHost + caFile + certFile + keyFile.
	Kubeconfig string `yaml:"kubeconfig"`

	// JWKSCheck enables the in-process JWKS signature check. When enabled, a
	// token whose signature, issuer, audience, or expiration fails verification
	// against the cluster JWKS is rejected. The check is cheap: keys are fetched
	// periodically and cached, then verification runs in-process. The signing
	// keys and issuer are discovered from the API server using the same
	// credentials as TokenReview. Requires audiences to be set.
	//
	// It defaults to on (a nil pointer means enabled). Defaulting on protects the
	// Kubernetes API server: a flood of bogus tokens is rejected in-process
	// before any TokenReview round-trip, so the service does not amplify a denial
	// of service onto the API server. Operators who understand the trade-off can
	// disable it by setting it to false.
	//
	// JWKSCheck and TokenReview are independent stages; at least one must be on.
	JWKSCheck *bool `yaml:"jwksCheck"`

	// TokenReview enables the authoritative TokenReview stage, which round-trips
	// to the API server for every token and validates it against the cluster's
	// live state.
	//
	// It defaults to on (a nil pointer means enabled). An operator may set it to
	// false to rely on the in-process JWKS check alone (e.g. for throughput or to
	// tolerate brief API server downtime), in which case JWKSCheck must be on,
	// because at least one validation stage must remain active. Relying on JWKS
	// alone gives up the live-state check.
	TokenReview *bool `yaml:"tokenReview"`

	// AuthClient overrides the default-built TokenReview client. Primarily a
	// test seam — passed through to the inner TokenReviewValidator. Mirrors how
	// pkg/validator/github.Config carries KeyProvider through to the inner
	// pkg/validator/jwt.Validator.
	AuthClient authenticationv1.AuthenticationV1Interface `yaml:"-"`

	// jwksValidator overrides the JWKS check stage. Test seam, mirrors
	// AuthClient. When nil and the JWKS check is enabled, NewValidator builds one
	// from the API server's discovered OIDC configuration.
	jwksValidator validator.TokenValidator

	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics `yaml:"-"`
}

func (c *Config) Unmarshal(raw *yaml.Node) error {
	return raw.Decode(c)
}

// enabled resolves an optional on/off flag: a nil pointer takes the default,
// otherwise the explicit value wins. Used so JWKSCheck and TokenReview can
// distinguish "unset" (apply default) from an explicit false.
func enabled(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (c *Config) ValidateConfig() error {
	var errs []error

	if len(c.AllowedNamespaces) == 0 && len(c.AllowedServiceAccounts) == 0 {
		errs = append(errs, errors.New("at least one of allowedNamespaces or allowedServiceAccounts must be specified"))
	}

	jwksOn := enabled(c.JWKSCheck, true)
	tokenReviewOn := enabled(c.TokenReview, true)

	// At least one validation stage must remain active; otherwise the validator
	// would accept every token. Both default on, so this requires explicitly
	// disabling both.
	if !jwksOn && !tokenReviewOn {
		errs = append(errs, errors.New("at least one of jwksCheck or tokenReview must be enabled"))
	}

	// The JWKS check verifies the token audience against the configured list, so
	// it cannot run without one. Because it defaults on, audiences is effectively
	// required unless jwksCheck is explicitly disabled.
	if jwksOn && len(c.Audiences) == 0 {
		errs = append(errs, errors.New("audiences is required when jwksCheck is enabled"))
	}

	// API server connectivity comes from the kubeconfig / in-cluster fallback,
	// not from individual fields. Only validate that the explicit path exists
	// if one is set; absence of a path is fine because the resolver will fall
	// back to in-cluster credentials or to KUBECONFIG / $HOME/.kube/config.
	if c.Kubeconfig != "" {
		if _, err := os.Stat(c.Kubeconfig); err != nil {
			errs = append(errs, fmt.Errorf("kubeconfig not found at %q: %w", c.Kubeconfig, err))
		}
	}

	return errors.Join(errs...)
}

func (c *Config) NewValidator() (validator.TokenValidatorAndSelectorGenerator, error) {
	return NewValidator(*c)
}

// Validator wraps a TokenReviewValidator to add operator policy: cluster-name
// injection into the claim map and namespace / service-account allowlists.
// Mirrors how pkg/validator/github.Validator wraps pkg/validator/jwt.Validator.
type Validator struct {
	// jwksCheck and inner are independent validation stages; at least one is
	// non-nil. jwksCheck is the in-process JWKS signature check; inner is the
	// authoritative TokenReview stage, nil when TokenReview is disabled. When
	// both run, JWKS runs first and TokenReview's claims are authoritative.
	jwksCheck              validator.TokenValidator
	inner                  *TokenReviewValidator
	clusterName            string
	allowedNamespaces      []string
	allowedServiceAccounts []string
	metrics                validator.Metrics
}

// NewValidator constructs a Validator wrapping a freshly-built
// TokenReviewValidator. Operator-facing config invariants are enforced by
// ValidateConfig; this defensive re-check protects programmatic callers
// that build a Config directly (e.g., tests) and would otherwise produce
// a Validator that accepts every token. Error message matches
// ValidateConfig's wording for consistency.
func NewValidator(cfg Config) (*Validator, error) {
	if len(cfg.AllowedNamespaces) == 0 && len(cfg.AllowedServiceAccounts) == 0 {
		return nil, fmt.Errorf("at least one of allowedNamespaces or allowedServiceAccounts must be specified")
	}

	jwksOn := enabled(cfg.JWKSCheck, true)
	tokenReviewOn := enabled(cfg.TokenReview, true)

	// Build the JWKS check stage when enabled. The injected jwksValidator wins
	// (test seam); otherwise it is built from the API server's discovered OIDC
	// configuration.
	jwksCheck := cfg.jwksValidator
	if jwksCheck == nil && jwksOn {
		if len(cfg.Audiences) == 0 {
			return nil, fmt.Errorf("audiences is required when jwksCheck is enabled")
		}
		var err error
		jwksCheck, err = newJWKSCheckValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS check validator: %w", err)
		}
	}

	// Build the authoritative TokenReview stage when enabled. When off, jwksCheck
	// must exist so the Validator is not a no-op that accepts every token.
	var inner *TokenReviewValidator
	if tokenReviewOn {
		var err error
		inner, err = NewTokenReviewValidator(TokenReviewConfig{
			Audiences:  cfg.Audiences,
			Kubeconfig: cfg.Kubeconfig,
			AuthClient: cfg.AuthClient,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create token review validator: %w", err)
		}
	}

	if inner == nil && jwksCheck == nil {
		return nil, fmt.Errorf("at least one of jwksCheck or tokenReview must be enabled")
	}

	return &Validator{
		jwksCheck:              jwksCheck,
		inner:                  inner,
		clusterName:            cfg.ClusterName,
		allowedNamespaces:      cfg.AllowedNamespaces,
		allowedServiceAccounts: cfg.AllowedServiceAccounts,
		metrics:                cfg.Metrics,
	}, nil
}

// Validate runs the configured validation stages, then injects k8s_cluster_name
// into the claim map and enforces the configured allowlists. Implements
// validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
	var claims validator.Claims

	// Stage 1: optional JWKS signature check. Rejects a token with a bad
	// signature, issuer, audience, or expiration. The JWKS check works from
	// cached keys, so it keeps functioning during brief API server downtime. Its
	// claims are used downstream only when TokenReview is disabled.
	if v.jwksCheck != nil {
		jwksClaims, err := v.jwksCheck.Validate(ctx, token, purpose)
		if err != nil {
			return nil, fmt.Errorf("JWKS check failed: %w", err)
		}
		claims = jwksClaims
	}

	// Stage 2: authoritative TokenReview, unless disabled. When it runs its
	// claims are authoritative and override the JWKS claims.
	if v.inner != nil {
		tokenReviewClaims, err := v.inner.Validate(ctx, token, purpose)
		if err != nil {
			return nil, err
		}
		claims = tokenReviewClaims
	}

	// Inject the operator-configured cluster name so templates can reference
	// {{.k8s_cluster_name}} bound to the cluster this Validator authenticates against.
	raw := claims.GetRaw()
	if v.clusterName != "" {
		raw["k8s_cluster_name"] = v.clusterName
	}

	if err := v.checkAllowLists(raw); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkAllowLists enforces AND logic: when both lists are configured, the
// token must match both the namespace allowlist and the service-account allowlist.
// Takes the raw claim map as input and converts it via claimsFromRaw, which
// tolerates both modern projected and legacy in-cluster SA token shapes; the
// allowlist comparisons read the typed Claims rather than the raw keys.
func (v *Validator) checkAllowLists(raw map[string]interface{}) error {
	c := claimsFromRaw(raw)
	if len(v.allowedNamespaces) > 0 {
		if !validator.IsValueAllowed(c.Namespace, v.allowedNamespaces) {
			return fmt.Errorf("namespace %q is not in the allowed list", c.Namespace)
		}
	}
	if len(v.allowedServiceAccounts) > 0 {
		sa := c.Namespace + "/" + c.ServiceAccountName
		if !validator.IsValueAllowed(sa, v.allowedServiceAccounts) {
			return fmt.Errorf("service account %q is not in the allowed list", sa)
		}
	}
	return nil
}

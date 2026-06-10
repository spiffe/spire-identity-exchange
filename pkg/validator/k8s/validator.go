// Package k8s provides a Kubernetes service-account token validator that
// authenticates tokens via the Kubernetes TokenReview API and/or an in-process
// JWKS signature check, and emits SPIRE selectors from the resulting claims. It
// implements validator.TokenValidator and validator.SelectorGenerator.
package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
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
	ClusterName string `json:"clusterName"`

	// Audiences are forwarded to the TokenReview Spec.Audiences so Kubernetes
	// binds the authentication decision to the audiences this service expects.
	// Strongly recommended: configure a dedicated audience (e.g. "spire-identity-exchange").
	Audiences []string `json:"audiences"`

	// AllowedNamespaces restricts which Kubernetes namespaces may exchange a token.
	// Each entry is a bare namespace name with optional trailing wildcard
	// (e.g. "prod", "team-*"). At least one of AllowedNamespaces or
	// AllowedServiceAccounts must be set.
	AllowedNamespaces []string `json:"allowedNamespaces"`

	// AllowedServiceAccounts restricts which service accounts may exchange a token.
	// Each entry is "namespace/serviceAccountName" with optional trailing wildcard
	// (e.g. "prod/web", "team-*/runner"). At least one of AllowedNamespaces or
	// AllowedServiceAccounts must be set.
	AllowedServiceAccounts []string `json:"allowedServiceAccounts"`

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
	Kubeconfig string `json:"kubeconfig"`

	// JWKSCheck enables a JWKS signature check. When enabled, a token whose
	// signature, issuer, audience, or expiration fails verification against the
	// cluster JWKS is rejected. JWKS check gates on cryptographic validity; it is
	// cheap because keys are fetched periodically and cached, then verification
	// runs in-process. The signing keys and issuer are discovered from the API
	// server using the same credentials as TokenReview. Requires audiences to be set.
	//
	// JWKSCheck and TokenReview are independent stages. At least one must be
	// active: JWKSCheck defaults off, TokenReview defaults on (see
	// DisableTokenReview), so the zero value runs TokenReview alone.
	JWKSCheck bool `json:"jwksCheck"`

	// DisableTokenReview turns off the authoritative TokenReview stage. By
	// default TokenReview runs (the zero value keeps it on). TokenReview is the
	// heavier check because it round-trips to the API server for every token, so
	// an operator may disable it and rely on the in-process JWKS check alone
	// (e.g. for throughput or to tolerate brief API server downtime). When
	// disabled, JWKSCheck must be enabled, because at least one validation stage
	// must remain active. Note the trade-off: TokenReview is what validates the
	// token against the cluster's live state, so relying on JWKS alone gives up
	// that check.
	DisableTokenReview bool `json:"disableTokenReview"`

	// AuthClient overrides the default-built TokenReview client. Primarily a
	// test seam — passed through to the inner TokenReviewValidator. Mirrors how
	// pkg/validator/github.Config carries KeyProvider through to the inner
	// pkg/validator/jwt.Validator.
	AuthClient authenticationv1.AuthenticationV1Interface `json:"-"`

	// jwksValidator overrides the JWKS check stage. Test seam, mirrors
	// AuthClient. When nil and JWKSCheck is true, NewValidator builds one
	// from the API server's discovered OIDC configuration.
	jwksValidator validator.TokenValidator

	// Metrics allows injecting a metrics collector for operation tracking.
	// If nil, metrics collection is silently skipped.
	Metrics validator.Metrics `json:"-"`
}

func (c *Config) Unmarshal(raw json.RawMessage) error {
	return json.Unmarshal(raw, c)
}

func (c *Config) ValidateConfig() error {
	var errs []error

	if len(c.AllowedNamespaces) == 0 && len(c.AllowedServiceAccounts) == 0 {
		errs = append(errs, errors.New("at least one of allowedNamespaces or allowedServiceAccounts must be specified"))
	}

	// The JWKS check verifies the token audience against the configured
	// list, so it cannot run without one.
	if c.JWKSCheck && len(c.Audiences) == 0 {
		errs = append(errs, errors.New("audiences is required when jwksCheck is enabled"))
	}

	// At least one validation stage must remain active. TokenReview defaults on,
	// so the only way to end up with neither is disabling it without jwksCheck.
	if c.DisableTokenReview && !c.JWKSCheck {
		errs = append(errs, errors.New("jwksCheck is required when disableTokenReview is set"))
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
	// non-nil. jwksCheck is the optional in-process JWKS signature check; inner
	// is the authoritative TokenReview stage, nil when DisableTokenReview is set.
	// When both run, JWKS runs first and TokenReview's claims are authoritative.
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

	// Build the optional JWKS check stage. The injected jwksValidator wins
	// (test seam); otherwise it is built from the API server's discovered OIDC
	// configuration when JWKSCheck is enabled.
	jwksCheck := cfg.jwksValidator
	if jwksCheck == nil && cfg.JWKSCheck {
		if len(cfg.Audiences) == 0 {
			return nil, fmt.Errorf("audiences is required when jwksCheck is enabled")
		}
		var err error
		jwksCheck, err = newJWKSCheckValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS check validator: %w", err)
		}
	}

	// Build the authoritative TokenReview stage unless disabled. When disabled,
	// jwksCheck must exist so the Validator is not a no-op that accepts every token.
	var inner *TokenReviewValidator
	if !cfg.DisableTokenReview {
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
		return nil, fmt.Errorf("jwksCheck is required when disableTokenReview is set")
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

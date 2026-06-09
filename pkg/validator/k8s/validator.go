// Package k8s provides a Kubernetes service-account token validator that
// authenticates tokens via the Kubernetes TokenReview API and emits SPIRE
// selectors from the resulting claims. It implements
// validator.TokenValidator and validator.SelectorGenerator.
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

	// JWKSCheck enables a JWKS signature check before TokenReview. When
	// enabled, a token whose signature, issuer, audience, or expiration fails
	// verification against the cluster JWKS is rejected without a TokenReview
	// round-trip to the API server. JWKS check gates on cryptographic validity;
	// TokenReview additionally validates the token against the cluster's live state.
	// The signing keys and
	// issuer are discovered from the API server using the same credentials as
	// TokenReview and cached. Requires audiences to be set.
	JWKSCheck bool `json:"jwksCheck"`

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
	// jwksCheck is the optional JWKS signature check stage. When non-nil
	// it runs before the inner TokenReview stage. Kept as an independent stage
	// so a future flag can disable TokenReview and rely on JWKS alone.
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

	inner, err := NewTokenReviewValidator(TokenReviewConfig{
		Audiences:  cfg.Audiences,
		Kubeconfig: cfg.Kubeconfig,
		AuthClient: cfg.AuthClient,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token review validator: %w", err)
	}

	// Build the optional JWKS check stage. The injected jwksValidator wins
	// (test seam); otherwise it is built from the API server's discovered OIDC
	// configuration when JWKSCheck is enabled.
	jwksCheck := cfg.jwksValidator
	if jwksCheck == nil && cfg.JWKSCheck {
		if len(cfg.Audiences) == 0 {
			return nil, fmt.Errorf("audiences is required when jwksCheck is enabled")
		}
		jwksCheck, err = newJWKSCheckValidator(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS check validator: %w", err)
		}
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

// Validate delegates token authentication to the inner TokenReviewValidator,
// then injects k8s_cluster_name into the claim map and enforces the configured
// allowlists. Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
	// Stage 1: optional JWKS signature check. Rejects a token with a bad
	// signature, issuer, audience, or expiration before the authoritative
	// TokenReview round-trip. The JWKS check works from cached keys, so it also
	// keeps functioning during brief API server downtime.
	if v.jwksCheck != nil {
		if _, err := v.jwksCheck.Validate(ctx, token, purpose); err != nil {
			return nil, fmt.Errorf("JWKS check failed: %w", err)
		}
	}

	// Stage 2: authoritative TokenReview.
	claims, err := v.inner.Validate(ctx, token, purpose)
	if err != nil {
		return nil, err
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

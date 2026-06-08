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
// validator registry under the "k8s_sa_token" plugin name.
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
	// Kubernetes API server for TokenReview calls. Leave empty to use the
	// standard fallback chain: in-cluster credentials first (when SIE itself
	// runs as a pod), then $KUBECONFIG, then $HOME/.kube/config. A kubeconfig
	// natively expresses every K8s auth flavor (in-cluster SA token, mTLS,
	// bearer token, AWS IAM / GKE / Azure exec plugins, SPIRE-issued SVID via
	// exec plugin), so a single field replaces what would otherwise be
	// apiHost + caFile + certFile + keyFile.
	Kubeconfig string `json:"kubeconfig"`

	// AuthClient overrides the default-built TokenReview client. Primarily a
	// test seam — passed through to the inner TokenReviewValidator. Mirrors how
	// pkg/validator/github.Config carries KeyProvider through to the inner
	// pkg/validator/jwt.Validator.
	AuthClient authenticationv1.AuthenticationV1Interface `json:"-"`

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
	inner                  *TokenReviewValidator
	clusterName            string
	allowedNamespaces      []string
	allowedServiceAccounts []string
	metrics                validator.Metrics
}

// NewValidator constructs a Validator wrapping a freshly-built
// TokenReviewValidator.
func NewValidator(cfg Config) (*Validator, error) {
	if len(cfg.AllowedNamespaces) == 0 && len(cfg.AllowedServiceAccounts) == 0 {
		return nil, fmt.Errorf("at least one of allowed_namespaces or allowed_service_accounts must be configured")
	}

	inner, err := NewTokenReviewValidator(TokenReviewConfig{
		Audiences:  cfg.Audiences,
		Kubeconfig: cfg.Kubeconfig,
		AuthClient: cfg.AuthClient,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token review validator: %w", err)
	}

	return &Validator{
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
// Reads from the typed Claims (which tolerates both modern projected and
// legacy in-cluster token shapes) rather than the raw map.
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

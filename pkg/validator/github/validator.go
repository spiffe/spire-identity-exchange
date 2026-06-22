// Package github provides a GitHub Actions OIDC token validator built on
// the generic jwt.Validator. It adds GitHub-specific allowlist checks
// and SPIRE selector generation.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtvalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"go.yaml.in/yaml/v3"
)

const (
	DefaultIssuer = "https://token.actions.githubusercontent.com"
)

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
	return &Config{}, nil
}

// Config holds configuration for the GitHub OIDC validator.
type Config struct {
	IssuerURL               string   `yaml:"issuerURL"`
	Audiences               []string `yaml:"audiences"`
	AllowedRepositoryOwners []string `yaml:"allowedRepositoryOwners"`
	AllowedRepositories     []string `yaml:"allowedRepositories"`
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
	err := jwtvalidator.ValidateIssuerURL(c.IssuerURL, c.AllowHTTP)
	if err != nil {
		return err
	}
	if len(c.Audiences) == 0 {
		return errors.New("at least one audience must be specified")
	}
	if len(c.AllowedRepositories) == 0 && len(c.AllowedRepositoryOwners) == 0 {
		return errors.New("at least one of allowedRepositories or allowedRepositoryOwners must be specified")
	}
	return nil
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

	jv, err := jwtvalidator.NewValidator(jwtvalidator.Config{
		IssuerURL:   issuer,
		Audiences:   cfg.Audiences,
		KeyProvider: cfg.KeyProvider,
		AllowHTTP:   cfg.AllowHTTP,
		Metrics:     cfg.Metrics,
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


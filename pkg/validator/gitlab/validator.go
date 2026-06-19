package gitlab

import (
	"context"
	"errors"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtvalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
	"gopkg.in/yaml.v3"
)

const (
	DefaultIssuer = "https://gitlab.com"
)

func TokenValidatorLoaderGenerator() (validator.TokenValidatorLoader, error) {
	return &Config{}, nil
}

type Config struct {
	IssuerURL             string                `yaml:"issuerURL"`
	Audiences             []string              `yaml:"audiences"`
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
	if !c.AllowHTTP && strings.HasPrefix(c.IssuerURL, "http://") {
		return errors.New("http:// issuer URLs are not allowed unless AllowHTTP is true")
	}
	if len(c.Audiences) == 0 {
		return errors.New("at least one audience must be specified")
	}
	if len(c.AllowedProjectPaths) == 0 && len(c.AllowedNamespacePaths) == 0 {
		return errors.New("at least one of allowedProjectPaths or allowedNamespacePaths must be specified")
	}
	return nil
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

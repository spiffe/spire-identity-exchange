package gitlab

import (
	"context"
	"fmt"
	"strings"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	jwtvalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/jwt"
)

const (
	DefaultIssuer = "https://gitlab.com"
)

type Config struct {
	IssuerURL             string
	Audiences             []string
	AllowedProjectPaths   []string
	AllowedNamespacePaths []string
	KeyProvider           validator.KeyProvider
	AllowHTTP             bool
	Metrics               validator.Metrics
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

func (v *Validator) Validate(ctx context.Context, token string) (validator.Claims, error) {
	claims, err := v.jwtValidator.Validate(ctx, token)
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
		if !isValueAllowed(projectPath, v.allowedProjectPaths) {
			return fmt.Errorf("project path %q is not in the allowed list", projectPath)
		}
	}
	if len(v.allowedNamespacePaths) > 0 {
		namespacePath, _ := raw["namespace_path"].(string)
		if !isValueAllowed(namespacePath, v.allowedNamespacePaths) {
			return fmt.Errorf("namespace path %q is not in the allowed list", namespacePath)
		}
	}
	return nil
}

func isValueAllowed(value string, allowedValues []string) bool {
	for _, av := range allowedValues {
		if strings.HasSuffix(av, "*") {
			pattern := strings.TrimSuffix(av, "*")
			if strings.HasPrefix(value, pattern) {
				return true
			}
		} else if value == av {
			return true
		}
	}
	return false
}

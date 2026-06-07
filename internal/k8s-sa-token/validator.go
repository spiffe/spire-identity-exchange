package k8ssatoken

import (
	"context"
	"fmt"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	k8svalidator "github.com/spiffe/spire-identity-exchange/pkg/validator/k8s"
	"go.uber.org/zap"
)

// Validator validates Kubernetes service account tokens. It wraps a
// pkg/validator/k8s.TokenReviewValidator (the verification primitive) and
// injects the operator-configured cluster name into the resulting claim map.
// Implements validator.TokenValidator.
type Validator struct {
	apiHost     string
	clusterName string
	inner       *k8svalidator.TokenReviewValidator
	logger      *zap.Logger
}

// NewValidator creates a K8s SA token validator. The underlying TokenReview
// client (and its HTTP/TLS state) is built once here and reused across requests.
func NewValidator(cfg config.K8sSATokenConfig, logger *zap.Logger) (*Validator, error) {
	if cfg.APIHost == "" {
		return nil, fmt.Errorf("k8sSAToken.apiHost is required")
	}

	inner, err := k8svalidator.NewTokenReviewValidator(k8svalidator.TokenReviewConfig{
		APIHost:   cfg.APIHost,
		Audiences: cfg.Audiences,
		CAFile:    cfg.TLS.CAFile,
		CertFile:  cfg.TLS.CertFile,
		KeyFile:   cfg.TLS.KeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token review validator: %w", err)
	}

	logger.Info("Initialized K8s SA token validator",
		zap.String("apiHost", cfg.APIHost),
		zap.Strings("audiences", cfg.Audiences))

	return &Validator{
		apiHost:     cfg.APIHost,
		clusterName: cfg.ClusterName,
		inner:       inner,
		logger:      logger,
	}, nil
}

// Validate delegates token authentication to the inner TokenReviewValidator and
// injects k8s_cluster_name into the claim map. Implements validator.TokenValidator.
//
// The TokenReview is always sent to the operator-configured apiHost — never to
// a host derived from the token's iss claim, which would be attacker-controlled
// before verification.
func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
	v.logger.Info("Validating token via configured K8s API server", zap.String("apiHost", v.apiHost))

	claims, err := v.inner.Validate(ctx, token, purpose)
	if err != nil {
		return nil, err
	}

	if v.clusterName != "" {
		claims.GetRaw()["k8s_cluster_name"] = v.clusterName
	}

	jwtClaims := claims.(*validator.JWTClaims)
	v.logger.Info("Token validated successfully",
		zap.String("issuer", jwtClaims.Issuer),
		zap.String("subject", jwtClaims.Subject))

	return claims, nil
}

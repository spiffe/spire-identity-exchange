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
	clusterName string
	inner       *k8svalidator.TokenReviewValidator
	logger      *zap.Logger
}

// NewValidator creates a K8s SA token validator. The underlying TokenReview
// client (and its HTTP/TLS state) is built once here and reused across requests.
// API server connectivity comes from the kubeconfig / in-cluster fallback
// resolved inside the inner TokenReviewValidator — not from individual
// apiHost / TLS fields.
func NewValidator(cfg config.K8sSATokenConfig, logger *zap.Logger) (*Validator, error) {
	inner, err := k8svalidator.NewTokenReviewValidator(k8svalidator.TokenReviewConfig{
		Audiences:  cfg.Audiences,
		Kubeconfig: cfg.Kubeconfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token review validator: %w", err)
	}

	logger.Info("Initialized K8s SA token validator",
		zap.String("kubeconfig", cfg.Kubeconfig),
		zap.Strings("audiences", cfg.Audiences))

	return &Validator{
		clusterName: cfg.ClusterName,
		inner:       inner,
		logger:      logger,
	}, nil
}

// Validate delegates token authentication to the inner TokenReviewValidator and
// injects k8s_cluster_name into the claim map. Implements validator.TokenValidator.
//
// The TokenReview always lands on the API server the inner client's kubeconfig
// (or in-cluster credentials) target — never on a host derived from the token's
// iss claim, which would be attacker-controlled before verification.
func (v *Validator) Validate(ctx context.Context, token string, purpose validator.Purpose) (validator.Claims, error) {
	v.logger.Info("Validating token via configured K8s API server")

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

package k8ssatoken

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
)

// Validator validates Kubernetes service account tokens.
// It implements the validator.TokenValidator interface.
type Validator struct {
	// Kubernetes API server URL (operator-configured; NEVER derived from the token).
	apiHost string
	// Operator-configured cluster identifier injected into claims for SPIFFE ID
	// derivation. Sourced from config only — never from the request.
	clusterName string
	// Pre-built TokenReview verifier. The underlying clientset is goroutine-safe and
	// reuses HTTP/TLS connections to the API server across requests.
	verifier utils.K8sSaTokenVerifier
	// Logger for logging
	logger *zap.Logger
}

// NewValidator creates a new K8s SA token validator. The TokenReview verifier is
// constructed once here so the underlying Kubernetes client (and its HTTP/TLS state)
// is reused across requests rather than rebuilt per validation.
func NewValidator(cfg config.K8sSATokenConfig, logger *zap.Logger) (*Validator, error) {
	if cfg.APIHost == "" {
		return nil, fmt.Errorf("k8sSAToken.apiHost is required")
	}

	verifier, err := utils.NewK8sSaTokenVerifier(
		cfg.APIHost,
		cfg.Audiences,
		cfg.TLS.CertFile,
		cfg.TLS.KeyFile,
		cfg.TLS.CAFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token verifier: %w", err)
	}

	logger.Info("Initialized K8s SA token validator",
		zap.String("apiHost", cfg.APIHost),
		zap.Strings("audiences", cfg.Audiences))

	return &Validator{
		apiHost:     cfg.APIHost,
		clusterName: cfg.ClusterName,
		verifier:    verifier,
		logger:      logger,
	}, nil
}

// Validate validates a Kubernetes service account token via the K8s TokenReview API
// and returns the JWT claims. Implements validator.TokenValidator.
//
// The TokenReview is always sent to the operator-configured apiHost — never to a host
// derived from the token's iss claim, which would be attacker-controlled before verification.
func (v *Validator) Validate(ctx context.Context, token string, _ validator.Purpose) (validator.Claims, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// Parse the token unverified solely to surface claims for SPIFFE ID derivation.
	// The TokenReview call (below) is the authoritative authentication step.
	rawClaims := make(jwt.MapClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	v.logger.Info("Validating token via configured K8s API server", zap.String("apiHost", v.apiHost))

	username, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// The TokenReview-authenticated principal must match the JWT `sub`. Without this
	// cross-check, a different (non-SA-but-API-server-accepted) JWT could supply
	// arbitrary claims for SPIFFE ID derivation; the Verify-side SA-prefix check is
	// the first half of this defense, and matching sub completes it.
	jwtSub, _ := rawClaims["sub"].(string)
	if jwtSub != username {
		return nil, fmt.Errorf("JWT sub %q does not match TokenReview principal %q", jwtSub, username)
	}

	// Populate both RegisteredClaims and RawClaims via the Claims UnmarshalJSON.
	claimsJSON, err := json.Marshal(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to encode claims: %w", err)
	}
	var claims utils.Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	// Inject the operator-configured cluster name so templates can reference
	// {{.k8s_cluster_name}} bound to the cluster this Validator authenticates against.
	raw := claims.RawClaims
	if raw == nil {
		raw = make(map[string]interface{}, 1)
	}
	if v.clusterName != "" {
		raw["k8s_cluster_name"] = v.clusterName
	}

	v.logger.Info("Token validated successfully", zap.String("issuer", claims.Issuer), zap.String("subject", claims.Subject))

	// Convert internal utils.Claims to the shared pkg/validator.JWTClaims interface.
	var expiry int64
	if claims.ExpiresAt != nil {
		expiry = claims.ExpiresAt.Unix()
	}
	var notBefore int64
	if claims.NotBefore != nil {
		notBefore = claims.NotBefore.Unix()
	}
	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}

	return &validator.JWTClaims{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		JTI:       claims.ID,
		Expiry:    expiry,
		NotBefore: notBefore,
		IssuedAt:  issuedAt,
		Raw:       raw,
	}, nil
}

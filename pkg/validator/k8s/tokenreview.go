package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// saUsernamePrefix is the K8s convention for service-account principals returned
// by the TokenReview API. Any other principal — node, OIDC user, bootstrap token
// — would be a non-SA bearer token and must not be accepted by this validator.
const saUsernamePrefix = "system:serviceaccount:"

// TokenReviewValidator authenticates Kubernetes service-account tokens via the
// Kubernetes TokenReview API and returns the JWT claims. It implements
// validator.TokenValidator and is intended to be wrapped by a higher-level
// validator (e.g. Validator) that adds operator-level policy such as cluster
// name injection and allowlists — analogous to how github.Validator wraps
// pkg/validator/jwt.Validator.
//
// The TokenReview call is the authoritative authentication step. The JWT is
// parsed without signature verification solely to surface claims for SPIFFE ID
// derivation and selector generation, after the TokenReview-authenticated
// principal is cross-checked against the JWT sub.
type TokenReviewValidator struct {
	authClient authenticationv1.AuthenticationV1Interface
	audiences  []string
}

// TokenReviewConfig holds configuration for a TokenReviewValidator.
type TokenReviewConfig struct {
	// Audiences are forwarded to the TokenReview Spec.Audiences so Kubernetes
	// binds the authentication decision to the audiences this service expects.
	Audiences []string

	// Kubeconfig is an optional explicit path to a kubeconfig file that
	// describes the API server endpoint, the CA used to verify it, and the
	// credentials used to authenticate to it. Leave empty to use the standard
	// in-cluster → KUBECONFIG env → $HOME/.kube/config fallback chain handled
	// by getKubernetesConfig. A kubeconfig composes natively with every K8s
	// authentication style (in-cluster SA token, mTLS client certs, bearer
	// token, AWS IAM / GKE / Azure exec plugins, SPIRE-issued client SVID via
	// exec plugin or cert/key paths).
	Kubeconfig string

	// AuthClient overrides the default-built TokenReview client. Primarily a
	// test seam — when nil, NewTokenReviewValidator builds a client via
	// getKubernetesConfig.
	AuthClient authenticationv1.AuthenticationV1Interface
}

// NewTokenReviewValidator constructs a TokenReviewValidator. When
// cfg.AuthClient is non-nil it is used directly (intended for tests);
// otherwise a TokenReview-backed client is built via getKubernetesConfig
// (which honors in-cluster credentials first, then kubeconfig).
// The underlying clientset is goroutine-safe and reuses HTTP/TLS connections to
// the API server across requests.
func NewTokenReviewValidator(cfg TokenReviewConfig) (*TokenReviewValidator, error) {
	authClient := cfg.AuthClient
	if authClient == nil {
		restCfg, err := getKubernetesConfig(cfg.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubernetes client config: %w", err)
		}
		restCfg.QPS = 20.0
		restCfg.Burst = 30.0
		clientset, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		authClient = clientset.AuthenticationV1()
	}
	return &TokenReviewValidator{
		authClient: authClient,
		audiences:  cfg.Audiences,
	}, nil
}

// getKubernetesConfig builds a *rest.Config using the standard K8s client
// resolution order:
//
//  1. In-cluster — kubelet-injected ServiceAccount token, CA, and
//     KUBERNETES_SERVICE_{HOST,PORT}. Works automatically when SIE runs as a
//     pod; no operator-supplied paths needed.
//  2. Kubeconfig — explicit path from cfg.Kubeconfig wins; otherwise the
//     loading rules fall back to $KUBECONFIG (env), then $HOME/.kube/config.
//     A kubeconfig file expresses every K8s auth flavor (mTLS, bearer token,
//     exec plugin for AWS/GKE/Azure/SPIRE), so a single field replaces what
//     would otherwise be apiHost + caFile + certFile + keyFile.
func getKubernetesConfig(kubeconfigPath string) (*rest.Config, error) {
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	} else if !errors.Is(err, rest.ErrNotInCluster) {
		return nil, fmt.Errorf("in-cluster config probe failed: %w", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}
	return cfg, nil
}

// Validate authenticates a Kubernetes service-account token via TokenReview and
// returns the JWT claims. Implements validator.TokenValidator. The Purpose
// parameter is ignored — TokenReview semantics don't vary by SVID purpose, same
// as pkg/validator/jwt.Validator.
func (v *TokenReviewValidator) Validate(ctx context.Context, token string, _ validator.Purpose) (validator.Claims, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// Parse the token unverified solely to surface claims for SPIFFE ID
	// derivation and selector generation. The TokenReview call below is the
	// authoritative authentication step.
	rawClaims := gojwt.MapClaims{}
	if _, _, err := new(gojwt.Parser).ParseUnverified(token, rawClaims); err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	username, err := v.tokenReview(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// The TokenReview-authenticated principal must match the JWT `sub`. Without
	// this cross-check, a different (non-SA-but-API-server-accepted) JWT could
	// supply arbitrary claims for SPIFFE ID derivation; the SA-prefix check in
	// tokenReview is the first half of this defense, and matching sub completes it.
	jwtSub, _ := rawClaims["sub"].(string)
	if jwtSub != username {
		return nil, fmt.Errorf("JWT sub %q does not match TokenReview principal %q", jwtSub, username)
	}

	issuer, _ := rawClaims["iss"].(string)
	jti, _ := rawClaims["jti"].(string)

	var aud []string
	if a, err := rawClaims.GetAudience(); err == nil {
		aud = []string(a)
	}

	return &validator.JWTClaims{
		Issuer:    issuer,
		Subject:   jwtSub,
		Audience:  aud,
		JTI:       jti,
		Expiry:    numericDateUnix(rawClaims, "exp"),
		NotBefore: numericDateUnix(rawClaims, "nbf"),
		IssuedAt:  numericDateUnix(rawClaims, "iat"),
		Raw:       map[string]interface{}(rawClaims),
	}, nil
}

// tokenReview performs the actual TokenReview call. When audiences are
// configured, they are sent in TokenReview Spec.Audiences so Kubernetes will
// only authenticate tokens minted for one of those audiences, and the
// response's status audiences must intersect with the configured list.
func (v *TokenReviewValidator) tokenReview(ctx context.Context, token string) (string, error) {
	if v.authClient == nil {
		return "", fmt.Errorf("authentication client is nil")
	}

	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: v.audiences,
		},
	}

	result, err := v.authClient.TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to call TokenReview API: %w", err)
	}

	if !result.Status.Authenticated {
		return "", fmt.Errorf("SA token authentication failed: %s", result.Status.Error)
	}

	// TokenReview returns Authenticated=true for any bearer credential the API
	// server accepts (SA tokens, user tokens, bootstrap tokens, OIDC, ...).
	// Require the principal to be a service account so a non-SA JWT can't slip
	// through and feed arbitrary claims into the SPIFFE ID template downstream.
	username := result.Status.User.Username
	if !strings.HasPrefix(username, saUsernamePrefix) {
		return "", fmt.Errorf("authenticated principal %q is not a service account", username)
	}

	if len(v.audiences) > 0 {
		if !audiencesIntersect(v.audiences, result.Status.Audiences) {
			return "", fmt.Errorf("token audiences %v do not match expected audiences %v", result.Status.Audiences, v.audiences)
		}
	}
	return username, nil
}

func audiencesIntersect(expected, got []string) bool {
	want := make(map[string]struct{}, len(expected))
	for _, a := range expected {
		want[a] = struct{}{}
	}
	for _, a := range got {
		if _, ok := want[a]; ok {
			return true
		}
	}
	return false
}

// numericDateUnix returns a JWT NumericDate claim as a Unix timestamp. JSON
// decoding may surface the value as float64 (default), json.Number, or int64
// depending on the encoder; tolerate all three.
func numericDateUnix(raw gojwt.MapClaims, key string) int64 {
	switch v := raw[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n
		}
	}
	return 0
}

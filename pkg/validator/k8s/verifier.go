package k8s

import (
	"context"
	"fmt"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

// saUsernamePrefix is the K8s convention for service-account principals returned by
// the TokenReview API. Any other principal — node, OIDC user, bootstrap token — would
// be a non-SA bearer token and must not be accepted by this validator.
const saUsernamePrefix = "system:serviceaccount:"

// SaTokenVerifier defines the contract for verifying a Kubernetes service-account
// token via the TokenReview API. Verify returns the authenticated username
// (e.g. system:serviceaccount:ns:sa) on success so callers can cross-check it
// against the JWT sub claim before deriving identity from the unverified JWT.
type SaTokenVerifier interface {
	Verify(ctx context.Context, token string) (string, error)
}

type saTokenVerifierImpl struct {
	authClient authenticationv1.AuthenticationV1Interface
	audiences  []string
}

// newSaTokenVerifier creates a verifier from a typed authentication client.
func newSaTokenVerifier(authClient authenticationv1.AuthenticationV1Interface, audiences []string) SaTokenVerifier {
	return &saTokenVerifierImpl{authClient: authClient, audiences: audiences}
}

// NewSaTokenVerifier builds a TokenReview-backed verifier from API server connection
// parameters. audiences are forwarded to the TokenReview Spec.Audiences so Kubernetes
// binds the authentication decision to the audience this service expects; the returned
// status audiences are checked to intersect with this list.
func NewSaTokenVerifier(k8sAPIHost string, audiences []string, k8sClientCertFile, k8sClientKeyFile, k8sCAFile string) (SaTokenVerifier, error) {
	cfg := newK8sClientConfig(k8sAPIHost, k8sClientCertFile, k8sClientKeyFile, k8sCAFile)
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return newSaTokenVerifier(clientset.AuthenticationV1(), audiences), nil
}

func newK8sClientConfig(k8sAPIHost, k8sClientCertFile, k8sClientKeyFile, k8sCAFile string) *rest.Config {
	var c rest.Config
	c.Host = k8sAPIHost
	c.TLSClientConfig.CAFile = k8sCAFile
	c.TLSClientConfig.CertFile = k8sClientCertFile
	c.TLSClientConfig.KeyFile = k8sClientKeyFile
	c.QPS = 20.0
	c.Burst = 30.0
	return &c
}

// Verify verifies a Kubernetes service account token.
// When audiences are configured, they are sent in TokenReview Spec.Audiences so
// Kubernetes will only authenticate tokens minted for one of those audiences, and
// the response's status audiences must intersect with the configured list.
func (v *saTokenVerifierImpl) Verify(ctx context.Context, token string) (string, error) {
	if v.authClient == nil {
		return "", fmt.Errorf("authentication client is nil")
	}

	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: v.audiences,
		},
	}

	result, err := v.authClient.TokenReviews().Create(
		ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to call TokenReview API: %w", err)
	}

	if !result.Status.Authenticated {
		return "", fmt.Errorf("SA token authentication failed: %s", result.Status.Error)
	}

	// TokenReview returns Authenticated=true for any bearer credential the API server
	// accepts (SA tokens, user tokens, bootstrap tokens, OIDC, ...). Require the
	// principal to be a service account so a non-SA JWT can't slip through and feed
	// arbitrary claims into the SPIFFE ID template downstream.
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

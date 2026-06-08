package k8ssatoken

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewValidator(t *testing.T) {
	logger := zap.NewNop()

	// Isolate from any host kubeconfig the loader would otherwise discover via
	// $KUBECONFIG or $HOME/.kube/config — the test should depend only on what
	// the test case configures, and on the in-cluster probe (which fails on
	// the dev host, falling through to the kubeconfig path).
	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", t.TempDir())

	// Need a real-on-disk kubeconfig for the happy path; the loader requires a
	// resolvable config, and we never dial — kubernetes.NewForConfig is lazy.
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	const validKubeconfigYAML = `
apiVersion: v1
kind: Config
clusters:
- name: stub
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: stub
  user:
    token: stub-token
contexts:
- name: stub
  context:
    cluster: stub
    user: stub
current-context: stub
`
	if err := os.WriteFile(kubeconfigPath, []byte(validKubeconfigYAML), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	testCases := []struct {
		name      string
		config    config.K8sSATokenConfig
		expectErr bool
	}{
		{
			name: "explicit nonexistent kubeconfig path: errors",
			config: config.K8sSATokenConfig{
				Kubeconfig: "/nonexistent/kubeconfig",
			},
			expectErr: true,
		},
		{
			name: "valid kubeconfig: builds client",
			config: config.K8sSATokenConfig{
				Kubeconfig: kubeconfigPath,
			},
		},
		{
			name: "with audiences configured",
			config: config.K8sSATokenConfig{
				Kubeconfig: kubeconfigPath,
				Audiences:  []string{"spire-identity-exchange"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := NewValidator(tc.config, logger)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, val)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, val)
		})
	}
}

func TestValidateToken(t *testing.T) {
	logger := zap.NewNop()

	t.Setenv("KUBECONFIG", "")
	t.Setenv("HOME", t.TempDir())

	// Build a minimal but syntactically valid kubeconfig so NewValidator
	// succeeds; we never dial the API server in this test — kubernetes.NewForConfig
	// is lazy and Validate exits before the network call for the bad-token cases.
	kubeconfigPath := filepath.Join(t.TempDir(), "kubeconfig")
	const validKubeconfigYAML = `
apiVersion: v1
kind: Config
clusters:
- name: stub
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: stub
  user:
    token: stub-token
contexts:
- name: stub
  context:
    cluster: stub
    user: stub
current-context: stub
`
	if err := os.WriteFile(kubeconfigPath, []byte(validKubeconfigYAML), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	cfg := config.K8sSATokenConfig{Kubeconfig: kubeconfigPath}

	val, err := NewValidator(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	testCases := []struct {
		name      string
		token     string
		expectErr bool
	}{
		{
			name:      "empty token",
			token:     "",
			expectErr: true,
		},
		{
			name:      "invalid JWT token",
			token:     "invalid.jwt.token",
			expectErr: true,
		},
	}

	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenInfo, err := val.Validate(ctx, tc.token, validator.X509Purpose())

			if tc.expectErr && err == nil {
				assert.Error(t, err, "expected error but got none")
			}

			if !tc.expectErr && err != nil {
				assert.NoError(t, err, "expected no error but got: %v", err)
			}

			if !tc.expectErr && tokenInfo == nil {
				assert.NotNil(t, tokenInfo, "expected token info to be returned")
			}
		})
	}
}

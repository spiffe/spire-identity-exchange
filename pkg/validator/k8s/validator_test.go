package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfig(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	for _, p := range []string{ca, cert, key} {
		require.NoError(t, os.WriteFile(p, []byte("stub"), 0o600))
	}

	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config_namespaces",
			cfg: Config{
				APIHost:           "https://kubernetes.default.svc:443",
				AllowedNamespaces: []string{"prod"},
				TLS:               TLSConfig{CAFile: ca, CertFile: cert, KeyFile: key},
			},
		},
		{
			name: "valid_config_service_accounts",
			cfg: Config{
				APIHost:                "https://kubernetes.default.svc:443",
				AllowedServiceAccounts: []string{"prod/web"},
				TLS:                    TLSConfig{CAFile: ca, CertFile: cert, KeyFile: key},
			},
		},
		{
			name: "missing_apiHost",
			cfg: Config{
				AllowedNamespaces: []string{"prod"},
				TLS:               TLSConfig{CAFile: ca, CertFile: cert, KeyFile: key},
			},
			expectErr: true,
			errMsg:    "apiHost is required",
		},
		{
			name: "non_https_apiHost",
			cfg: Config{
				APIHost:           "http://kubernetes.default.svc:443",
				AllowedNamespaces: []string{"prod"},
				TLS:               TLSConfig{CAFile: ca, CertFile: cert, KeyFile: key},
			},
			expectErr: true,
			errMsg:    "apiHost must use https://",
		},
		{
			name: "missing_allowlists",
			cfg: Config{
				APIHost: "https://kubernetes.default.svc:443",
				TLS:     TLSConfig{CAFile: ca, CertFile: cert, KeyFile: key},
			},
			expectErr: true,
			errMsg:    "at least one of allowedNamespaces or allowedServiceAccounts",
		},
		{
			name: "missing_tls_files",
			cfg: Config{
				APIHost:           "https://kubernetes.default.svc:443",
				AllowedNamespaces: []string{"prod"},
			},
			expectErr: true,
			errMsg:    "tls.caFile is required",
		},
		{
			name: "tls_file_not_found",
			cfg: Config{
				APIHost:           "https://kubernetes.default.svc:443",
				AllowedNamespaces: []string{"prod"},
				TLS: TLSConfig{
					CAFile:   filepath.Join(dir, "missing-ca.pem"),
					CertFile: cert,
					KeyFile:  key,
				},
			},
			expectErr: true,
			errMsg:    "tls.caFile not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.ValidateConfig()
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "minimum_required",
			cfg: Config{
				APIHost:           "https://kubernetes.default.svc:443",
				AllowedNamespaces: []string{"prod"},
				AuthClient:        &mockAuthV1Client{tokenValid: true},
			},
		},
		{
			name: "missing_apiHost",
			cfg: Config{
				AllowedNamespaces: []string{"prod"},
				AuthClient:        &mockAuthV1Client{tokenValid: true},
			},
			expectErr: true,
			errMsg:    "apiHost is required",
		},
		{
			name: "missing_allowlists",
			cfg: Config{
				APIHost:    "https://kubernetes.default.svc:443",
				AuthClient: &mockAuthV1Client{tokenValid: true},
			},
			expectErr: true,
			errMsg:    "at least one of allowed_namespaces or allowed_service_accounts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewValidator(tt.cfg)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, v)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

// TestCheckAllowLists exercises the wrapper-specific allowlist logic directly,
// without plumbing through a TokenReviewValidator. Mirrors gitlab/github's
// approach.
func TestCheckAllowLists(t *testing.T) {
	tests := []struct {
		name                   string
		allowedNamespaces      []string
		allowedServiceAccounts []string
		raw                    map[string]interface{}
		expectErr              bool
		errMsg                 string
	}{
		{
			name:              "namespace_allowed",
			allowedNamespaces: []string{"ns"},
			raw:               projectedClaims("ns", "sa"),
		},
		{
			name:              "namespace_wildcard_allowed",
			allowedNamespaces: []string{"prod-*"},
			raw:               projectedClaims("prod-1", "sa"),
		},
		{
			name:              "namespace_rejected",
			allowedNamespaces: []string{"ns"},
			raw:               projectedClaims("other", "sa"),
			expectErr:         true,
			errMsg:            `namespace "other"`,
		},
		{
			name:                   "service_account_allowed",
			allowedServiceAccounts: []string{"ns/web"},
			raw:                    projectedClaims("ns", "web"),
		},
		{
			name:                   "service_account_rejected",
			allowedServiceAccounts: []string{"ns/web"},
			raw:                    projectedClaims("ns", "other"),
			expectErr:              true,
			errMsg:                 `service account "ns/other"`,
		},
		{
			name:                   "both_required_and_match",
			allowedNamespaces:      []string{"ns"},
			allowedServiceAccounts: []string{"ns/web"},
			raw:                    projectedClaims("ns", "web"),
		},
		{
			name:                   "both_required_namespace_fails",
			allowedNamespaces:      []string{"ns"},
			allowedServiceAccounts: []string{"ns/web"},
			raw:                    projectedClaims("other", "web"),
			expectErr:              true,
			errMsg:                 `namespace "other"`,
		},
		{
			name:                   "both_required_sa_fails",
			allowedNamespaces:      []string{"ns"},
			allowedServiceAccounts: []string{"ns/web"},
			raw:                    projectedClaims("ns", "other"),
			expectErr:              true,
			errMsg:                 `service account "ns/other"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				allowedNamespaces:      tt.allowedNamespaces,
				allowedServiceAccounts: tt.allowedServiceAccounts,
			}
			err := v.checkAllowLists(tt.raw)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateWrapsInner is a smoke test confirming the wrapper passes
// authentication through to the inner TokenReviewValidator, injects
// k8s_cluster_name from operator config, and rejects on allowlist failure.
// The exhaustive TokenReview-side cases live in tokenreview_test.go.
func TestValidateWrapsInner(t *testing.T) {
	cfg := Config{
		APIHost:           "https://kubernetes.default.svc:443",
		ClusterName:       "prod-cluster",
		AllowedNamespaces: []string{"ns"},
		AuthClient: &mockAuthV1Client{
			tokenValid:     true,
			returnUsername: "system:serviceaccount:ns:sa",
		},
	}

	v, err := NewValidator(cfg)
	require.NoError(t, err)

	t.Run("happy_path_injects_cluster_name", func(t *testing.T) {
		// Token shaped for projected SA — namespace from kubernetes.io is what
		// checkAllowLists reads, so synthesize via a richer token.
		token := mkProjectedToken("system:serviceaccount:ns:sa", "ns", "sa")
		claims, err := v.Validate(context.Background(), token, validator.X509Purpose())
		require.NoError(t, err)
		assert.Equal(t, "prod-cluster", claims.GetRaw()["k8s_cluster_name"])
	})

	t.Run("inner_errors_bubble_up", func(t *testing.T) {
		// Empty token is rejected by the inner TokenReviewValidator.
		_, err := v.Validate(context.Background(), "", validator.X509Purpose())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token cannot be empty")
	})

	t.Run("allowlist_failure_after_successful_inner", func(t *testing.T) {
		// Configure a different validator whose mock returns the same username
		// the token's sub will carry, but whose namespace is outside the allowlist.
		denyCfg := Config{
			APIHost:           "https://kubernetes.default.svc:443",
			AllowedNamespaces: []string{"prod-only"},
			AuthClient: &mockAuthV1Client{
				tokenValid:     true,
				returnUsername: "system:serviceaccount:ns:sa",
			},
		}
		denyV, err := NewValidator(denyCfg)
		require.NoError(t, err)

		_, err = denyV.Validate(context.Background(), mkProjectedToken("system:serviceaccount:ns:sa", "ns", "sa"), validator.X509Purpose())
		require.Error(t, err)
		assert.Contains(t, err.Error(), `namespace "ns" is not in the allowed list`)
	})
}

func TestGenerateSelectors(t *testing.T) {
	tests := []struct {
		name    string
		raw     map[string]interface{}
		wantHas []string
	}{
		{
			name: "projected_token_shape",
			raw: map[string]interface{}{
				"sub":              "system:serviceaccount:ns:sa",
				"k8s_cluster_name": "prod",
				"kubernetes.io": map[string]interface{}{
					"namespace": "ns",
					"serviceaccount": map[string]interface{}{
						"name": "sa",
						"uid":  "sa-uid",
					},
					"pod": map[string]interface{}{
						"name": "pod-1",
						"uid":  "pod-uid",
					},
					"node": map[string]interface{}{
						"name": "node-1",
						"uid":  "node-uid",
					},
				},
			},
			wantHas: []string{
				"cluster_name:prod",
				"namespace:ns",
				"service_account_name:sa",
				"service_account_uid:sa-uid",
				"pod_name:pod-1",
				"pod_uid:pod-uid",
				"node_name:node-1",
				"node_uid:node-uid",
				"sub:system:serviceaccount:ns:sa",
			},
		},
		{
			name: "legacy_in_cluster_token_shape",
			raw: map[string]interface{}{
				"sub": "system:serviceaccount:ns:sa",
				"kubernetes.io/serviceaccount/namespace":            "ns",
				"kubernetes.io/serviceaccount/service-account.name": "sa",
				"kubernetes.io/serviceaccount/service-account.uid":  "sa-uid",
			},
			wantHas: []string{
				"namespace:ns",
				"service_account_name:sa",
				"service_account_uid:sa-uid",
				"sub:system:serviceaccount:ns:sa",
			},
		},
		{
			name:    "empty_claims_returns_no_selectors",
			raw:     map[string]interface{}{},
			wantHas: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{}
			got := v.GenerateSelectors(&validator.JWTClaims{Raw: tt.raw})

			gotSet := make(map[string]struct{}, len(got))
			for _, s := range got {
				assert.Equal(t, SelectorType, s.Type)
				gotSet[s.Value] = struct{}{}
			}

			for _, want := range tt.wantHas {
				_, ok := gotSet[want]
				assert.True(t, ok, "missing selector %q (got %v)", want, sortedKeys(gotSet))
			}
			if tt.wantHas == nil {
				assert.Empty(t, got)
			}
		})
	}
}

// projectedClaims returns a raw claims map shaped like a modern projected SA
// token with the given namespace and service-account name.
func projectedClaims(namespace, sa string) map[string]interface{} {
	return map[string]interface{}{
		"sub": "system:serviceaccount:" + namespace + ":" + sa,
		"kubernetes.io": map[string]interface{}{
			"namespace":      namespace,
			"serviceaccount": map[string]interface{}{"name": sa},
		},
	}
}

// mkProjectedToken mints an unsigned JWT shaped like a modern projected SA token.
// Used by wrapper tests where the inner TokenReviewValidator's JWT-parse step
// needs to see kubernetes.io claims so the allowlist check can read them.
func mkProjectedToken(sub, namespace, sa string) string {
	header := map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"}
	claims := map[string]interface{}{
		"sub": sub,
		"kubernetes.io": map[string]interface{}{
			"namespace":      namespace,
			"serviceaccount": map[string]interface{}{"name": sa},
		},
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb) + ".signature"
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

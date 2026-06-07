package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubVerifier is a SaTokenVerifier that returns canned results, letting the
// validator tests exercise the Validate() path without spinning up a real K8s
// API server. The real TokenReview client is covered separately in verifier_test.go.
type stubVerifier struct {
	username string
	err      error
}

func (s *stubVerifier) Verify(ctx context.Context, token string) (string, error) {
	return s.username, s.err
}

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
				Verifier:          &stubVerifier{username: "ignored"},
			},
		},
		{
			name: "missing_apiHost",
			cfg: Config{
				AllowedNamespaces: []string{"prod"},
				Verifier:          &stubVerifier{username: "ignored"},
			},
			expectErr: true,
			errMsg:    "apiHost is required",
		},
		{
			name: "missing_allowlists",
			cfg: Config{
				APIHost:  "https://kubernetes.default.svc:443",
				Verifier: &stubVerifier{username: "ignored"},
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

func TestValidate(t *testing.T) {
	type stubClaims struct {
		Sub       string                 `json:"sub"`
		Iss       string                 `json:"iss"`
		Aud       []string               `json:"aud,omitempty"`
		Exp       int64                  `json:"exp,omitempty"`
		Nbf       int64                  `json:"nbf,omitempty"`
		Iat       int64                  `json:"iat,omitempty"`
		Jti       string                 `json:"jti,omitempty"`
		K8sIONest map[string]interface{} `json:"kubernetes.io,omitempty"`
	}

	mkToken := func(c stubClaims) string {
		header := map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"}
		hb, _ := json.Marshal(header)
		cb, _ := json.Marshal(c)
		return base64.RawURLEncoding.EncodeToString(hb) + "." +
			base64.RawURLEncoding.EncodeToString(cb) + ".signature"
	}

	// k8sIO returns a kubernetes.io claim nest for namespace "ns", SA "sa".
	k8sIO := func() map[string]interface{} {
		return map[string]interface{}{
			"namespace": "ns",
			"serviceaccount": map[string]interface{}{
				"name": "sa",
				"uid":  "11111111-2222-3333-4444-555555555555",
			},
		}
	}

	tests := []struct {
		name                   string
		token                  string
		verifier               *stubVerifier
		clusterName            string
		allowedNamespaces      []string
		allowedServiceAccounts []string
		expectErr              string
		assert                 func(t *testing.T, c validator.Claims)
	}{
		{
			name:              "empty_token_rejected",
			token:             "",
			verifier:          &stubVerifier{username: "system:serviceaccount:ns:sa"},
			allowedNamespaces: []string{"ns"},
			expectErr:         "token cannot be empty",
		},
		{
			name:              "malformed_token_rejected",
			token:             "not.a.jwt",
			verifier:          &stubVerifier{username: "system:serviceaccount:ns:sa"},
			allowedNamespaces: []string{"ns"},
			expectErr:         "failed to extract JWT claims",
		},
		{
			name: "verifier_error_propagated",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:sa", Iss: "k8s", Aud: []string{"a"}, Exp: 200,
				K8sIONest: k8sIO(),
			}),
			verifier:          &stubVerifier{err: errors.New("boom")},
			allowedNamespaces: []string{"ns"},
			expectErr:         "token verification failed",
		},
		{
			name: "sub_mismatch_rejected",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:other", Iss: "k8s", Aud: []string{"a"}, Exp: 200,
				K8sIONest: k8sIO(),
			}),
			verifier:          &stubVerifier{username: "system:serviceaccount:ns:sa"},
			allowedNamespaces: []string{"ns"},
			expectErr:         "does not match TokenReview principal",
		},
		{
			name: "happy_path_with_cluster_name_injected",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:sa", Iss: "k8s", Aud: []string{"a"}, Exp: 200, Nbf: 100, Iat: 150, Jti: "abc",
				K8sIONest: k8sIO(),
			}),
			verifier:          &stubVerifier{username: "system:serviceaccount:ns:sa"},
			clusterName:       "prod",
			allowedNamespaces: []string{"ns"},
			assert: func(t *testing.T, c validator.Claims) {
				raw := c.GetRaw()
				assert.Equal(t, "prod", raw["k8s_cluster_name"])
				assert.Equal(t, "abc", c.GetUniqueID())
				assert.Equal(t, int64(200), c.GetExpiration())
				j := c.(*validator.JWTClaims)
				assert.Equal(t, "system:serviceaccount:ns:sa", j.Subject)
				assert.Equal(t, "k8s", j.Issuer)
				assert.Equal(t, []string{"a"}, j.Audience)
				assert.Equal(t, int64(100), j.NotBefore)
				assert.Equal(t, int64(150), j.IssuedAt)
			},
		},
		{
			name: "empty_cluster_name_not_injected",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:sa", Iss: "k8s", Aud: []string{"a"}, Exp: 200,
				K8sIONest: k8sIO(),
			}),
			verifier:          &stubVerifier{username: "system:serviceaccount:ns:sa"},
			allowedNamespaces: []string{"ns"},
			assert: func(t *testing.T, c validator.Claims) {
				_, ok := c.GetRaw()["k8s_cluster_name"]
				assert.False(t, ok, "k8s_cluster_name must not be injected when unset")
			},
		},
		{
			name: "namespace_allowlist_rejects_other_namespace",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:other:sa", Iss: "k8s", Exp: 200,
				K8sIONest: map[string]interface{}{
					"namespace":      "other",
					"serviceaccount": map[string]interface{}{"name": "sa"},
				},
			}),
			verifier:          &stubVerifier{username: "system:serviceaccount:other:sa"},
			allowedNamespaces: []string{"ns"},
			expectErr:         `namespace "other" is not in the allowed list`,
		},
		{
			name: "namespace_allowlist_wildcard_accepted",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:prod-1:sa", Iss: "k8s", Exp: 200,
				K8sIONest: map[string]interface{}{
					"namespace":      "prod-1",
					"serviceaccount": map[string]interface{}{"name": "sa"},
				},
			}),
			verifier:          &stubVerifier{username: "system:serviceaccount:prod-1:sa"},
			allowedNamespaces: []string{"prod-*"},
		},
		{
			name: "service_account_allowlist_rejects_other_sa",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:other", Iss: "k8s", Exp: 200,
				K8sIONest: map[string]interface{}{
					"namespace":      "ns",
					"serviceaccount": map[string]interface{}{"name": "other"},
				},
			}),
			verifier:               &stubVerifier{username: "system:serviceaccount:ns:other"},
			allowedServiceAccounts: []string{"ns/web"},
			expectErr:              `service account "ns/other" is not in the allowed list`,
		},
		{
			name: "service_account_allowlist_exact_match_accepted",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:web", Iss: "k8s", Exp: 200,
				K8sIONest: map[string]interface{}{
					"namespace":      "ns",
					"serviceaccount": map[string]interface{}{"name": "web"},
				},
			}),
			verifier:               &stubVerifier{username: "system:serviceaccount:ns:web"},
			allowedServiceAccounts: []string{"ns/web"},
		},
		{
			name: "both_allowlists_require_both_to_match",
			token: mkToken(stubClaims{
				Sub: "system:serviceaccount:ns:other", Iss: "k8s", Exp: 200,
				K8sIONest: map[string]interface{}{
					"namespace":      "ns",
					"serviceaccount": map[string]interface{}{"name": "other"},
				},
			}),
			verifier:               &stubVerifier{username: "system:serviceaccount:ns:other"},
			allowedNamespaces:      []string{"ns"},
			allowedServiceAccounts: []string{"ns/web"},
			expectErr:              `service account "ns/other"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewValidator(Config{
				APIHost:                "https://kubernetes.default.svc:443",
				ClusterName:            tt.clusterName,
				AllowedNamespaces:      tt.allowedNamespaces,
				AllowedServiceAccounts: tt.allowedServiceAccounts,
				Verifier:               tt.verifier,
			})
			require.NoError(t, err)

			claims, err := v.Validate(context.Background(), tt.token, validator.X509Purpose())
			if tt.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErr)
				assert.Nil(t, claims)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, claims)
			if tt.assert != nil {
				tt.assert(t, claims)
			}
		})
	}
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

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

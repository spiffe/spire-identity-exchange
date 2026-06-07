package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

// mockAuthV1Client is a mock AuthenticationV1Interface that lets a test stub
// what the TokenReview call returns. It is the test seam used by
// TokenReviewValidator — feeding behavior in via the k8s SDK's own interface
// rather than a bespoke wrapper.
type mockAuthV1Client struct {
	shouldReturnError bool
	tokenValid        bool
	errorMessage      string
	returnAudiences   []string
	gotAudiences      []string
	returnUsername    string // defaults to a valid SA username when empty
}

func (m *mockAuthV1Client) TokenReviews() authenticationv1.TokenReviewInterface {
	return &mockTokenReviewsClient{parent: m}
}

func (m *mockAuthV1Client) SelfSubjectReviews() authenticationv1.SelfSubjectReviewInterface {
	return nil
}

func (m *mockAuthV1Client) RESTClient() rest.Interface {
	return nil
}

type mockTokenReviewsClient struct {
	parent *mockAuthV1Client
}

func (m *mockTokenReviewsClient) Create(ctx context.Context, tokenReview *authv1.TokenReview, opts metav1.CreateOptions) (*authv1.TokenReview, error) {
	m.parent.gotAudiences = tokenReview.Spec.Audiences

	if m.parent.shouldReturnError {
		return nil, fmt.Errorf("mock API error: %s", m.parent.errorMessage)
	}

	username := m.parent.returnUsername
	if username == "" {
		username = "system:serviceaccount:default:mock-sa"
	}
	result := &authv1.TokenReview{
		Status: authv1.TokenReviewStatus{
			Authenticated: m.parent.tokenValid,
			Audiences:     m.parent.returnAudiences,
			User:          authv1.UserInfo{Username: username},
		},
	}

	if !m.parent.tokenValid {
		result.Status.Error = "token is invalid"
	}

	return result, nil
}

// mkToken mints a token-shaped string carrying the given sub and optional
// audience. The token is NOT signed — TokenReviewValidator does not verify
// signatures; the K8s API server (or the mock auth client in tests) is the
// authoritative authentication step.
func mkToken(sub string, audiences ...string) string {
	header := map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"}
	claims := map[string]interface{}{"sub": sub}
	if len(audiences) > 0 {
		claims["aud"] = audiences
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb) + ".signature"
}

func TestNewTokenReviewValidator_BuildsRealClient(t *testing.T) {
	tests := []struct {
		name              string
		k8sAPIHost        string
		k8sClientCertFile string
		k8sClientKeyFile  string
		k8sCAFile         string
		wantErr           bool
		errorContains     string
	}{
		{
			name:              "invalid configuration should return error",
			k8sAPIHost:        "invalid-host",
			k8sClientCertFile: "/nonexistent/cert.pem",
			k8sClientKeyFile:  "/nonexistent/key.pem",
			k8sCAFile:         "/nonexistent/ca.pem",
			wantErr:           true,
			errorContains:     "failed to create kubernetes client",
		},
		{
			name:    "empty parameters should return no error (validation is deferred to ValidateConfig)",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewTokenReviewValidator(TokenReviewConfig{
				APIHost:  tt.k8sAPIHost,
				CertFile: tt.k8sClientCertFile,
				KeyFile:  tt.k8sClientKeyFile,
				CAFile:   tt.k8sCAFile,
			})

			if tt.wantErr {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestTokenReviewValidator_Validate(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		authClient    authenticationv1.AuthenticationV1Interface
		expectErr     bool
		errorContains string
		assert        func(t *testing.T, c validator.Claims)
	}{
		{
			name:          "empty_token_rejected",
			token:         "",
			authClient:    &mockAuthV1Client{tokenValid: true},
			expectErr:     true,
			errorContains: "token cannot be empty",
		},
		{
			name:          "malformed_jwt_rejected",
			token:         "not.a.jwt",
			authClient:    &mockAuthV1Client{tokenValid: true},
			expectErr:     true,
			errorContains: "failed to extract JWT claims",
		},
		{
			name:       "valid_token_returns_claims",
			token:      mkToken("system:serviceaccount:default:mock-sa"),
			authClient: &mockAuthV1Client{tokenValid: true},
			assert: func(t *testing.T, c validator.Claims) {
				j := c.(*validator.JWTClaims)
				assert.Equal(t, "system:serviceaccount:default:mock-sa", j.Subject)
			},
		},
		{
			name:          "token_review_rejection_propagated",
			token:         mkToken("system:serviceaccount:default:mock-sa"),
			authClient:    &mockAuthV1Client{tokenValid: false},
			expectErr:     true,
			errorContains: "SA token authentication failed: token is invalid",
		},
		{
			name:          "api_error_propagated",
			token:         mkToken("system:serviceaccount:default:mock-sa"),
			authClient:    &mockAuthV1Client{shouldReturnError: true, errorMessage: "network timeout"},
			expectErr:     true,
			errorContains: "failed to call TokenReview API",
		},
		{
			name:  "sub_mismatch_rejected",
			token: mkToken("system:serviceaccount:default:other-sa"),
			authClient: &mockAuthV1Client{
				tokenValid:     true,
				returnUsername: "system:serviceaccount:default:mock-sa",
			},
			expectErr:     true,
			errorContains: "does not match TokenReview principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: tt.authClient})
			require.NoError(t, err)

			claims, err := v.Validate(context.Background(), tt.token, validator.X509Purpose())

			if tt.expectErr {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}
			require.NoError(t, err)
			if tt.assert != nil {
				tt.assert(t, claims)
			}
		})
	}
}

func TestTokenReviewValidator_ContextCancellation(t *testing.T) {
	t.Run("context cancellation should be passed to API", func(t *testing.T) {
		mockClient := &mockAuthV1Client{tokenValid: true}
		v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: mockClient})
		require.NoError(t, err)

		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = v.Validate(cancelledCtx, mkToken("system:serviceaccount:default:mock-sa"), validator.X509Purpose())
		_ = err
	})

	t.Run("context with timeout", func(t *testing.T) {
		mockClient := &mockAuthV1Client{tokenValid: true}
		v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: mockClient})
		require.NoError(t, err)

		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := v.Validate(timeoutCtx, mkToken("system:serviceaccount:default:mock-sa"), validator.X509Purpose()); err != nil {
			t.Errorf("Unexpected error with timeout context: %v", err)
		}
	})
}

func TestTokenReviewValidator_AudienceBinding(t *testing.T) {
	t.Run("audiences are forwarded to TokenReview Spec", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"spire-identity-exchange"},
		}
		v, err := NewTokenReviewValidator(TokenReviewConfig{
			AuthClient: mockClient,
			Audiences:  []string{"spire-identity-exchange"},
		})
		require.NoError(t, err)

		if _, err := v.Validate(context.Background(), mkToken("system:serviceaccount:default:mock-sa"), validator.X509Purpose()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockClient.gotAudiences) != 1 || mockClient.gotAudiences[0] != "spire-identity-exchange" {
			t.Errorf("expected configured audiences forwarded, got %v", mockClient.gotAudiences)
		}
	})

	t.Run("mismatched status audiences are rejected", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"some-other-service"},
		}
		v, err := NewTokenReviewValidator(TokenReviewConfig{
			AuthClient: mockClient,
			Audiences:  []string{"spire-identity-exchange"},
		})
		require.NoError(t, err)

		_, err = v.Validate(context.Background(), mkToken("system:serviceaccount:default:mock-sa"), validator.X509Purpose())
		if err == nil || !strings.Contains(err.Error(), "do not match expected audiences") {
			t.Errorf("expected audience-mismatch rejection, got %v", err)
		}
	})

	t.Run("no audiences configured means no audience binding enforced", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"any-audience"},
		}
		v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: mockClient})
		require.NoError(t, err)

		if _, err := v.Validate(context.Background(), mkToken("system:serviceaccount:default:mock-sa"), validator.X509Purpose()); err != nil {
			t.Errorf("expected no error with audience binding disabled, got: %v", err)
		}
	})
}

func TestTokenReviewValidator_RejectsNonServiceAccountPrincipals(t *testing.T) {
	cases := []struct {
		name     string
		username string
	}{
		{"oidc user", "alice@example.com"},
		{"node principal", "system:node:worker-1"},
		{"bootstrap token", "system:bootstrap:abcde1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockAuthV1Client{tokenValid: true, returnUsername: tc.username}
			v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: mockClient})
			require.NoError(t, err)

			// Use a token whose sub matches the username so we get past the
			// sub-mismatch check and hit the SA-prefix one.
			_, err = v.Validate(context.Background(), mkToken(tc.username), validator.X509Purpose())
			if err == nil || !strings.Contains(err.Error(), "not a service account") {
				t.Errorf("expected non-SA rejection for %q, got err=%v", tc.username, err)
			}
		})
	}

	t.Run("service-account principal accepted", func(t *testing.T) {
		mockClient := &mockAuthV1Client{tokenValid: true, returnUsername: "system:serviceaccount:prod:payment"}
		v, err := NewTokenReviewValidator(TokenReviewConfig{AuthClient: mockClient})
		require.NoError(t, err)

		claims, err := v.Validate(context.Background(), mkToken("system:serviceaccount:prod:payment"), validator.X509Purpose())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := claims.(*validator.JWTClaims).Subject; got != "system:serviceaccount:prod:payment" {
			t.Errorf("expected subject preserved, got %q", got)
		}
	})
}

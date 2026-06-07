package k8s

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authenticationv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
)

const (
	validToken   = "valid-token"
	invalidToken = "invalid-token"
	testToken    = "test-token"
)

// mockAuthV1Client is a mock implementation of AuthenticationV1Interface for testing
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

func TestNewSaTokenVerifierInternal(t *testing.T) {
	tests := []struct {
		name       string
		authClient authenticationv1.AuthenticationV1Interface
		wantNil    bool
	}{
		{
			name: "with valid auth client",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        true,
			},
			wantNil: false,
		},
		{
			name:       "with nil auth client",
			authClient: nil,
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newSaTokenVerifier(tt.authClient, nil)
			if (got == nil) != tt.wantNil {
				t.Errorf("newSaTokenVerifier() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func TestNewSaTokenVerifier(t *testing.T) {
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
			name:              "empty parameters should return error",
			k8sAPIHost:        "",
			k8sClientCertFile: "",
			k8sClientKeyFile:  "",
			k8sCAFile:         "",
			wantErr:           false,
			errorContains:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSaTokenVerifier(tt.k8sAPIHost, nil, tt.k8sClientCertFile, tt.k8sClientKeyFile, tt.k8sCAFile)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewSaTokenVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
				if got != nil {
					t.Error("Expected nil verifier when error occurs")
				}
			} else {
				if got == nil {
					t.Error("Expected non-nil verifier")
				}
			}
		})
	}
}

func TestSaTokenVerifierImplVerify(t *testing.T) {
	tests := []struct {
		name          string
		authClient    authenticationv1.AuthenticationV1Interface
		token         string
		ctx           context.Context
		expectError   bool
		errorContains string
	}{
		{
			name: "valid token should return no error",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        true,
			},
			token:       validToken,
			ctx:         context.Background(),
			expectError: false,
		},
		{
			name: "invalid token should return error",
			authClient: &mockAuthV1Client{
				shouldReturnError: false,
				tokenValid:        false,
			},
			token:         invalidToken,
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "SA token authentication failed: token is invalid",
		},
		{
			name: "API error should return error",
			authClient: &mockAuthV1Client{
				shouldReturnError: true,
				tokenValid:        false,
				errorMessage:      "network timeout",
			},
			token:         "some-token",
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "failed to call TokenReview API",
		},
		{
			name:          "nil auth client should return error",
			authClient:    nil,
			token:         "some-token",
			ctx:           context.Background(),
			expectError:   true,
			errorContains: "authentication client is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := newSaTokenVerifier(tt.authClient, nil)
			_, err := verifier.Verify(tt.ctx, tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			}
		})
	}
}

func TestSaTokenVerifierWithContextCancellation(t *testing.T) {
	t.Run("context cancellation should be passed to API", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			shouldReturnError: false,
			tokenValid:        true,
		}

		verifier := newSaTokenVerifier(mockClient, nil)

		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := verifier.Verify(cancelledCtx, testToken)
		_ = err
	})

	t.Run("context with timeout", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			shouldReturnError: false,
			tokenValid:        true,
		}

		verifier := newSaTokenVerifier(mockClient, nil)

		timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := verifier.Verify(timeoutCtx, validToken)
		if err != nil {
			t.Errorf("Unexpected error with timeout context: %v", err)
		}
	})
}

func TestSaTokenVerifierAudienceBinding(t *testing.T) {
	t.Run("audiences are forwarded to TokenReview Spec", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"spire-identity-exchange"},
		}
		verifier := newSaTokenVerifier(mockClient, []string{"spire-identity-exchange"})
		if _, err := verifier.Verify(context.Background(), validToken); err != nil {
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
		verifier := newSaTokenVerifier(mockClient, []string{"spire-identity-exchange"})
		_, err := verifier.Verify(context.Background(), validToken)
		if err == nil || !strings.Contains(err.Error(), "do not match expected audiences") {
			t.Errorf("expected audience-mismatch rejection, got %v", err)
		}
	})

	t.Run("no audiences configured means no audience binding enforced", func(t *testing.T) {
		mockClient := &mockAuthV1Client{
			tokenValid:      true,
			returnAudiences: []string{"any-audience"},
		}
		verifier := newSaTokenVerifier(mockClient, nil)
		if _, err := verifier.Verify(context.Background(), validToken); err != nil {
			t.Errorf("expected no error with audience binding disabled, got: %v", err)
		}
	})
}

func TestSaTokenVerifierRejectsNonServiceAccountPrincipals(t *testing.T) {
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
			verifier := newSaTokenVerifier(mockClient, nil)
			user, err := verifier.Verify(context.Background(), validToken)
			if err == nil || !strings.Contains(err.Error(), "not a service account") {
				t.Errorf("expected non-SA rejection for %q, got user=%q err=%v", tc.username, user, err)
			}
		})
	}

	t.Run("service-account principal accepted", func(t *testing.T) {
		mockClient := &mockAuthV1Client{tokenValid: true, returnUsername: "system:serviceaccount:prod:payment"}
		verifier := newSaTokenVerifier(mockClient, nil)
		user, err := verifier.Verify(context.Background(), validToken)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if user != "system:serviceaccount:prod:payment" {
			t.Errorf("expected username returned, got %q", user)
		}
	})
}

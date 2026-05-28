package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// --- Test Helpers ---

func createTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func createTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func createTestToken(t *testing.T, claims map[string]interface{}, privateKey interface{}, kid string) string {
	t.Helper()
	var signingMethod gojwt.SigningMethod
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = gojwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		signingMethod = gojwt.SigningMethodES256
	default:
		t.Fatalf("unsupported key type: %T", privateKey)
	}

	token := gojwt.NewWithClaims(signingMethod, gojwt.MapClaims(claims))
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

func createMockJWKSServer(t *testing.T, publicKey crypto.PublicKey, kid string) *httptest.Server {
	t.Helper()
	var alg string
	switch publicKey.(type) {
	case *rsa.PublicKey:
		alg = "RS256"
	case *ecdsa.PublicKey:
		alg = "ES256"
	}
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: publicKey, KeyID: kid, Algorithm: alg, Use: "sig"}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": server.URL + "/.well-known/jwks",
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

type mockMetrics struct {
	mu         sync.Mutex
	opCounts   []metricsCall
	opDurations []metricsCall
}

type metricsCall struct {
	component, plugin, operation, status string
}

func (m *mockMetrics) IncOperationCount(component, plugin, operation, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opCounts = append(m.opCounts, metricsCall{component, plugin, operation, status})
}

func (m *mockMetrics) ObserveOperationDuration(component, plugin, operation, status string, duration float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opDurations = append(m.opDurations, metricsCall{component, plugin, operation, status})
}

func validClaims(issuer, audience string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss":              issuer,
		"sub":              "repo:my-org/my-repo:ref:refs/heads/main",
		"aud":              audience,
		"exp":              float64(now.Add(time.Hour).Unix()),
		"iat":              float64(now.Unix()),
		"nbf":              float64(now.Unix()),
		"jti":              "test-jti-12345",
		"repository":       "my-org/my-repo",
		"repository_owner": "my-org",
		"ref":              "refs/heads/main",
		"ref_type":         "branch",
		"actor":            "test-user",
	}
}

// --- Tests ---

func TestNewValidator(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid_config",
			cfg: Config{
				IssuerURL: "https://token.actions.githubusercontent.com",
				Audiences: []string{"test-aud"},
			},
		},
		{
			name: "empty_issuer",
			cfg: Config{
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "issuer URL must not be empty",
		},
		{
			name: "no_audiences",
			cfg: Config{
				IssuerURL: "https://example.com",
			},
			expectErr: true,
			errMsg:    "at least one audience must be configured",
		},
		{
			name: "http_issuer_without_allow",
			cfg: Config{
				IssuerURL: "http://localhost",
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "scheme must be https",
		},
		{
			name: "http_issuer_with_allow",
			cfg: Config{
				IssuerURL: "http://localhost",
				Audiences: []string{"test-aud"},
				AllowHTTP: true,
			},
			expectErr: false,
		},
		{
			name: "issuer_with_query",
			cfg: Config{
				IssuerURL: "https://example.com?foo=bar",
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "query parameters are not allowed",
		},
		{
			name: "issuer_with_fragment",
			cfg: Config{
				IssuerURL: "https://example.com#frag",
				Audiences: []string{"test-aud"},
			},
			expectErr: true,
			errMsg:    "fragment is not allowed",
		},
		{
			name: "custom_key_provider",
			cfg: Config{
				IssuerURL:   "https://example.com",
				Audiences:   []string{"test-aud"},
				KeyProvider: NewDefaultKeyProvider("https://example.com", &http.Client{}, nil),
			},
			expectErr: false,
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
	rsaKey := createTestRSAKey(t)
	kid := "test-kid-1"

	jwksServer := createMockJWKSServer(t, &rsaKey.PublicKey, kid)
	issuer := jwksServer.URL
	audience := "test-aud"

	v, err := NewValidator(Config{
		IssuerURL: issuer,
		Audiences: []string{audience},
		AllowHTTP: true,
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		claims    map[string]interface{}
		key       interface{}
		kid       string
		expectErr bool
		errMsg    string
	}{
		{
			name:   "valid_token",
			claims: validClaims(issuer, audience),
			key:    rsaKey,
			kid:    kid,
		},
		{
			name: "expired_token",
			claims: func() map[string]interface{} {
				c := validClaims(issuer, audience)
				c["exp"] = float64(time.Now().Add(-time.Hour).Unix())
				return c
			}(),
			key:       rsaKey,
			kid:       kid,
			expectErr: true,
			errMsg:    "token validation failed",
		},
		{
			name: "wrong_issuer",
			claims: func() map[string]interface{} {
				c := validClaims("https://wrong-issuer.com", audience)
				return c
			}(),
			key:       rsaKey,
			kid:       kid,
			expectErr: true,
			errMsg:    "token validation failed",
		},
		{
			name: "wrong_audience",
			claims: func() map[string]interface{} {
				c := validClaims(issuer, "wrong-audience")
				return c
			}(),
			key:       rsaKey,
			kid:       kid,
			expectErr: true,
			errMsg:    "audience mismatch",
		},
		{
			name: "invalid_signature",
			claims: func() map[string]interface{} {
				return validClaims(issuer, audience)
			}(),
			key:       createTestRSAKey(t), // different key
			kid:       kid,
			expectErr: true,
			errMsg:    "token validation failed",
		},
		{
			name: "unknown_kid",
			claims: func() map[string]interface{} {
				return validClaims(issuer, audience)
			}(),
			key:       rsaKey,
			kid:       "unknown-kid",
			expectErr: true,
			errMsg:    "no key found for kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createTestToken(t, tt.claims, tt.key, tt.kid)
			result, err := v.Validate(context.Background(), token)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				// Verify claims are populated.
				jwtClaims, ok := result.(*validator.JWTClaims)
				require.True(t, ok)
				assert.Equal(t, issuer, jwtClaims.Issuer)
				assert.Equal(t, "test-jti-12345", jwtClaims.GetUniqueID())
				assert.NotNil(t, jwtClaims.GetRaw())
				assert.Equal(t, "my-org/my-repo", jwtClaims.GetRaw()["repository"])
			}
		})
	}
}

func TestValidate_Metrics(t *testing.T) {
	rsaKey := createTestRSAKey(t)
	kid := "test-kid-metrics"

	jwksServer := createMockJWKSServer(t, &rsaKey.PublicKey, kid)
	issuer := jwksServer.URL
	audience := "test-aud"

	m := &mockMetrics{}
	v, err := NewValidator(Config{
		IssuerURL: issuer,
		Audiences: []string{audience},
		AllowHTTP: true,
		Metrics:   m,
	})
	require.NoError(t, err)

	// Successful validation.
	token := createTestToken(t, validClaims(issuer, audience), rsaKey, kid)
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err)

	m.mu.Lock()
	require.NotEmpty(t, m.opCounts)
	lastCount := m.opCounts[len(m.opCounts)-1]
	assert.Equal(t, "validate_token", lastCount.operation)
	assert.Equal(t, "OK", lastCount.status)
	m.mu.Unlock()

	// Failed validation (invalid token).
	_, err = v.Validate(context.Background(), "invalid-token")
	require.Error(t, err)

	m.mu.Lock()
	lastCount = m.opCounts[len(m.opCounts)-1]
	assert.Equal(t, "validate_token", lastCount.operation)
	assert.Equal(t, "InvalidArgument", lastCount.status)
	m.mu.Unlock()
}

func TestValidateIssuerURL(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		allowHTTP bool
		expectErr bool
		errMsg    string
	}{
		{
			name:   "valid_https",
			issuer: "https://example.com",
		},
		{
			name:      "http_rejected",
			issuer:    "http://example.com",
			expectErr: true,
			errMsg:    "scheme must be https",
		},
		{
			name:      "http_allowed",
			issuer:    "http://localhost",
			allowHTTP: true,
		},
		{
			name:      "empty_host",
			issuer:    "https://",
			expectErr: true,
			errMsg:    "host must not be empty",
		},
		{
			name:      "query_rejected",
			issuer:    "https://example.com?q=1",
			expectErr: true,
			errMsg:    "query parameters are not allowed",
		},
		{
			name:      "fragment_rejected",
			issuer:    "https://example.com#frag",
			expectErr: true,
			errMsg:    "fragment is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuerURL(tt.issuer, tt.allowHTTP)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractKID(t *testing.T) {
	rsaKey := createTestRSAKey(t)

	t.Run("valid_token", func(t *testing.T) {
		token := createTestToken(t, validClaims("https://example.com", "aud"), rsaKey, "my-kid")
		kid, err := extractKID(token)
		require.NoError(t, err)
		assert.Equal(t, "my-kid", kid)
	})

	t.Run("missing_kid", func(t *testing.T) {
		// Create a token without kid.
		jwtToken := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{"sub": "test"})
		delete(jwtToken.Header, "kid")
		tokenString, err := jwtToken.SignedString(rsaKey)
		require.NoError(t, err)

		_, err = extractKID(tokenString)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "kid")
	})

	t.Run("invalid_token_string", func(t *testing.T) {
		_, err := extractKID("not-a-jwt")
		require.Error(t, err)
	})
}

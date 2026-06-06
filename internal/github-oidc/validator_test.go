package githuboidc

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
	"os"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	constant "github.com/spiffe/spire-identity-exchange/internal/const"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// Test data structure matching the testdata JSON
type testDataClaims struct {
	RealisticGithubOIDCToken                testClaim `json:"realistic_github_oidc_token"`
	RealisticGithubOIDCTokenWithEnvironment testClaim `json:"realistic_github_oidc_token_with_environment"`
}

type testClaim map[string]interface{}

// loadTestData loads test claims from the testdata JSON file
func loadTestData(t *testing.T) testDataClaims {
	data, err := os.ReadFile("../testdata/github_oidc_claims.json")
	require.NoError(t, err, "Failed to read testdata file")

	var testData testDataClaims
	err = json.Unmarshal(data, &testData)
	require.NoError(t, err, "Failed to parse testdata JSON")

	return testData
}

// createTestMetrics creates test metrics for testing
func createTestMetrics(t *testing.T) metrics.Metrics {
	testRegistry := prometheus.NewRegistry()
	return prommetrics.NewPluginMetrics(testRegistry, "test")
}

// Helper function to create test RSA key pair
func createTestRSAKey(t *testing.T) (*rsa.PrivateKey, crypto.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

// Helper function to create test ECDSA key pair
func createTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

// Helper function to create a signed JWT token
func createTestToken(t *testing.T, claims map[string]interface{}, privateKey interface{}, kid string) string {
	var signingMethod jwt.SigningMethod
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		signingMethod = jwt.SigningMethodES256
	default:
		t.Fatal("Unsupported key type")
	}

	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims(claims))
	token.Header[kidHeader] = kid

	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return tokenString
}

// Helper function to create a mock JWKS server
func createMockJWKSServer(t *testing.T, publicKey crypto.PublicKey, kid string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       publicKey,
			KeyID:     kid,
			Algorithm: "RS256",
			Use:       "sig",
		}

		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}

		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(jwks)
		require.NoError(t, err)
	}))
}

func TestNewValidator(t *testing.T) {
	ctx := context.Background()
	logger := zaptest.NewLogger(t)

	tests := []struct {
		name      string
		config    config.GitHubOIDCConfig
		expectErr bool
	}{
		{
			name: "Valid configuration",
			config: config.GitHubOIDCConfig{
				Issuer:              "https://token.actions.githubusercontent.com",
				Audiences:           []string{"spire-identity-exchange"},
				AllowedRepositories: []string{"*"},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testMetrics := createTestMetrics(t)
			validator, err := NewValidator(ctx, tt.config, testMetrics, logger)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)

				gv, ok := validator.(*githubValidator)
				assert.True(t, ok)
				assert.Equal(t, tt.config, gv.config)
				assert.NotNil(t, gv.logger)
				assert.NotNil(t, gv.keyCache)
				assert.NotNil(t, gv.httpClient)
				assert.NotNil(t, gv.metrics)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	testData := loadTestData(t)

	privateKey, publicKey := createTestRSAKey(t)
	kid := "test-key-id"

	server := createMockJWKSServer(t, publicKey, kid)
	defer server.Close()

	tests := []struct {
		name      string
		config    config.GitHubOIDCConfig
		claims    map[string]interface{}
		setupKey  func(*githubValidator)
		expectErr bool
		errMsg    string
	}{
		{
			name: "Valid token with all claims",
			config: config.GitHubOIDCConfig{
				Issuer:    "https://token.actions.githubusercontent.com",
				Audiences: []string{"spire-identity-exchange"},
			},
			claims: testData.RealisticGithubOIDCToken,
			setupKey: func(v *githubValidator) {
				v.keyCache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				v.keyCache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: false,
		},
		{
			name: "Token with issuer mismatch",
			config: config.GitHubOIDCConfig{
				Issuer:    "https://wrong.issuer.com",
				Audiences: []string{"spire-identity-exchange"},
			},
			claims: testData.RealisticGithubOIDCToken,
			setupKey: func(v *githubValidator) {
				v.keyCache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				v.keyCache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: true,
			errMsg:    "issuer",
		},
		{
			name: "Token with expired timestamp but skip enabled",
			config: config.GitHubOIDCConfig{
				Issuer:              "https://token.actions.githubusercontent.com",
				Audiences:           []string{"spire-identity-exchange"},
				SkipTokenExpiration: true,
			},
			claims: func() map[string]interface{} {
				c := make(map[string]interface{})
				for k, v := range testData.RealisticGithubOIDCToken {
					c[k] = v
				}
				c["exp"] = time.Now().Add(-1 * time.Hour).Unix()
				c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
				return c
			}(),
			setupKey: func(v *githubValidator) {
				v.keyCache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				v.keyCache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: false,
		},
		{
			name: "Missing kid header",
			config: config.GitHubOIDCConfig{
				Issuer:    "https://token.actions.githubusercontent.com",
				Audiences: []string{"spire-identity-exchange"},
			},
			claims: testData.RealisticGithubOIDCToken,
			setupKey: func(v *githubValidator) {
				v.keyCache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				v.keyCache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: true,
			errMsg:    "kid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testMetrics := createTestMetrics(t)
			validator := &githubValidator{
				config:  tt.config,
				logger:  logger,
				metrics: testMetrics,
				keyCache: &jwksCache{
					keys: atomic.Value{},
					ttl:  keyCacheValidityDuration,
				},
				httpClient: http.DefaultClient,
			}

			tt.setupKey(validator)

			var tokenString string
			if tt.name == "Missing kid header" {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(tt.claims))
				var err error
				tokenString, err = token.SignedString(privateKey)
				require.NoError(t, err)
			} else {
				tokenString = createTestToken(t, tt.claims, privateKey, kid)
			}

			claims := &utils.Claims{
				RawClaims: make(map[string]interface{}),
			}

			err := validator.validateToken(tokenString, claims)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, claims.RawClaims)
			}
		})
	}
}

func TestValidateAudiences(t *testing.T) {
	tests := []struct {
		name          string
		configAud     []string
		tokenAud      []string
		expectedValid bool
	}{
		{
			name:          "Single Audience match",
			configAud:     []string{"spire-identity-exchange"},
			tokenAud:      []string{"spire-identity-exchange"},
			expectedValid: true,
		},
		{
			name:          "No Audience match",
			configAud:     []string{"aud1", "aud2"},
			tokenAud:      []string{"spire-identity-exchange"},
			expectedValid: false,
		},
		{
			name:          "Empty token Audience",
			configAud:     []string{"spire-identity-exchange"},
			tokenAud:      []string{},
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &githubValidator{
				config: config.GitHubOIDCConfig{
					Audiences: tt.configAud,
				},
			}

			result := validator.validateAudiences(tt.tokenAud)
			assert.Equal(t, tt.expectedValid, result)
		})
	}
}

func TestValidateRepository(t *testing.T) {
	tests := []struct {
		name        string
		repo        string
		allowedList []string
		expectedOK  bool
	}{
		{
			name:        "Exact match",
			repo:        "myorg/test-repo",
			allowedList: []string{"myorg/test-repo"},
			expectedOK:  true,
		},
		{
			name:        "Wildcard match - org level",
			repo:        "myorg/test-repo",
			allowedList: []string{"myorg/*"},
			expectedOK:  true,
		},
		{
			name:        "Wildcard match - all repos",
			repo:        "any-org/any-repo",
			allowedList: []string{"*"},
			expectedOK:  true,
		},
		{
			name:        "No match",
			repo:        "other-org/test-repo",
			allowedList: []string{"myorg/*"},
			expectedOK:  false,
		},
		{
			name:        "Empty repository",
			repo:        "",
			allowedList: []string{"*"},
			expectedOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &githubValidator{
				config: config.GitHubOIDCConfig{
					AllowedRepositories: tt.allowedList,
				},
			}

			result := validator.validateRepository(tt.repo, validator.config)
			assert.Equal(t, tt.expectedOK, result)
		})
	}
}

func TestGetVerificationKeys(t *testing.T) {
	_, publicKey := createTestRSAKey(t)
	kid := "test-key-id"

	tests := []struct {
		name       string
		setupCache func(*jwksCache)
		expectErr  bool
		errMsg     string
	}{
		{
			name: "Valid keys in cache",
			setupCache: func(cache *jwksCache) {
				cache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				cache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: false,
		},
		{
			name: "Cache not initialized",
			setupCache: func(cache *jwksCache) {
				// Don't store anything
			},
			expectErr: true,
			errMsg:    "not initialized",
		},
		{
			name: "Empty keys in cache",
			setupCache: func(cache *jwksCache) {
				cache.keys.Store(map[string]crypto.PublicKey{})
				cache.expiresAt.Store(time.Now().Add(time.Hour))
			},
			expectErr: true,
			errMsg:    "empty",
		},
		{
			name: "Expired cache fails closed",
			setupCache: func(cache *jwksCache) {
				cache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				cache.expiresAt.Store(time.Now().Add(-time.Minute))
			},
			expectErr: true,
			errMsg:    "expired",
		},
		{
			name: "Missing expiresAt fails closed",
			setupCache: func(cache *jwksCache) {
				cache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
				// deliberately do not set expiresAt
			},
			expectErr: true,
			errMsg:    "expiry unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &jwksCache{
				keys: atomic.Value{},
				ttl:  keyCacheValidityDuration,
			}
			tt.setupCache(cache)

			validator := &githubValidator{
				keyCache: cache,
			}

			keys, err := validator.getVerificationKeys()

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, keys)
			}
		})
	}
}

func TestGetVerificationKeysNilCache(t *testing.T) {
	validator := &githubValidator{
		keyCache: nil,
	}

	keys, err := validator.getVerificationKeys()
	assert.Error(t, err)
	assert.Nil(t, keys)
	assert.Contains(t, err.Error(), "key cache is nil")
}

func TestFetchJWKS(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, publicKey := createTestRSAKey(t)
	kid := "test-key-id"

	tests := []struct {
		name      string
		setupSrv  func() *httptest.Server
		expectErr bool
		errMsg    string
	}{
		{
			name: "Successful fetch",
			setupSrv: func() *httptest.Server {
				return createMockJWKSServer(t, publicKey, kid)
			},
			expectErr: false,
		},
		{
			name: "Server returns 404",
			setupSrv: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			expectErr: true,
			errMsg:    "status: 404",
		},
		{
			name: "Server returns invalid JSON",
			setupSrv: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte("invalid json"))
				}))
			},
			expectErr: true,
			errMsg:    "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupSrv()
			defer server.Close()

			testMetrics := createTestMetrics(t)
			validator := &githubValidator{
				logger:     logger,
				metrics:    testMetrics,
				httpClient: http.DefaultClient,
			}

			ctx := context.Background()
			jwks, err := validator.fetchJWKS(ctx, server.URL)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwks)
				assert.NotEmpty(t, jwks.Keys)
			}
		})
	}
}

func TestValidate_Integration(t *testing.T) {
	logger := zaptest.NewLogger(t)
	testData := loadTestData(t)

	privateKey, publicKey := createTestRSAKey(t)
	kid := "test-key-id"

	server := createMockJWKSServer(t, publicKey, kid)
	defer server.Close()

	cfg := config.GitHubOIDCConfig{
		Issuer:              "https://token.actions.githubusercontent.com",
		Audiences:           []string{"spire-identity-exchange"},
		JWKSURI:             server.URL,
		AllowedRepositories: []string{"example-org/*"},
		RequiredClaims:      []string{"repository", "workflow"},
	}

	ctx := context.Background()
	testMetrics := createTestMetrics(t)
	validator, err := NewValidator(ctx, cfg, testMetrics, logger)
	require.NoError(t, err)

	gv := validator.(*githubValidator)
	gv.keyCache.keys.Store(map[string]crypto.PublicKey{kid: publicKey})
	gv.keyCache.expiresAt.Store(time.Now().Add(time.Hour))

	tokenString := createTestToken(t, testData.RealisticGithubOIDCToken, privateKey, kid)

	claims, err := validator.Validate(ctx, tokenString, v.X509Purpose())
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, "example-org/test-github-oidc-wf-token", utils.GetStringClaim(claims.GetRaw(), constant.ClaimRepository))
	assert.Equal(t, "Save OIDC Token", utils.GetStringClaim(claims.GetRaw(), constant.ClaimWorkflow))
}

func TestStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, publicKey := createTestRSAKey(t)
	kid := "test-key-id"

	server := createMockJWKSServer(t, publicKey, kid)
	defer server.Close()

	cfg := config.GitHubOIDCConfig{
		JWKSURI: server.URL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	testMetrics := createTestMetrics(t)
	validator, err := NewValidator(ctx, cfg, testMetrics, logger)
	require.NoError(t, err)

	gv := validator.(*githubValidator)

	err = gv.Start(ctx)
	assert.NoError(t, err)

	keys, err := gv.getVerificationKeys()
	assert.NoError(t, err)
	assert.NotEmpty(t, keys)
}

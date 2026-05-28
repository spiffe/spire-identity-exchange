package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetKey(t *testing.T) {
	rsaKey := createTestRSAKey(t)
	kid := "test-kid-cache"

	var fetchCount atomic.Int64
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		jwk := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
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
	defer server.Close()

	provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
	ctx := context.Background()

	t.Run("cache_miss_fetches_jwks", func(t *testing.T) {
		fetchCount.Store(0)
		key, err := provider.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.IsType(t, &rsa.PublicKey{}, key)
		assert.Equal(t, int64(1), fetchCount.Load())
	})

	t.Run("cache_hit", func(t *testing.T) {
		fetchCount.Store(0)
		key, err := provider.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, int64(0), fetchCount.Load()) // no HTTP request
	})

	t.Run("unknown_kid", func(t *testing.T) {
		_, err := provider.GetKey(ctx, "nonexistent-kid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no key found for kid")
	})

	t.Run("cache_expiry", func(t *testing.T) {
		// Force cache expiry.
		provider.mu.Lock()
		provider.cache.expiry = time.Now().Add(-time.Minute)
		provider.mu.Unlock()

		fetchCount.Store(0)
		key, err := provider.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, int64(1), fetchCount.Load()) // re-fetched
	})
}

func TestFetchJWKS(t *testing.T) {
	t.Run("valid_rsa_key", func(t *testing.T) {
		rsaKey := createTestRSAKey(t)
		server := createMockJWKSServer(t, &rsaKey.PublicKey, "rsa-kid")
		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)

		keys, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.IsType(t, &rsa.PublicKey{}, keys["rsa-kid"])
	})

	t.Run("valid_ecdsa_key", func(t *testing.T) {
		ecKey := createTestECDSAKey(t)
		server := createMockJWKSServer(t, &ecKey.PublicKey, "ec-kid")
		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)

		keys, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.IsType(t, &ecdsa.PublicKey{}, keys["ec-kid"])
	})

	t.Run("non_200_status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("server error"))
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 500")
	})

	t.Run("invalid_json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JWKS")
	})

	t.Run("no_valid_keys", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Empty JWKS.
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid signing keys")
	})

	t.Run("skip_non_sig_keys", func(t *testing.T) {
		rsaKey := createTestRSAKey(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sigKey := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "sig-kid", Algorithm: "RS256", Use: "sig"}
			encKey := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "enc-kid", Algorithm: "RS256", Use: "enc"}
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{sigKey, encKey}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		keys, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Contains(t, keys, "sig-kid")
		assert.NotContains(t, keys, "enc-kid")
	})
}

func TestDiscoverJWKSURI(t *testing.T) {
	t.Run("valid_discovery", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "https://example.com/.well-known/jwks",
			})
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		uri, err := provider.discoverJWKSURI(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/.well-known/jwks", uri)
	})

	t.Run("non_200_status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.discoverJWKSURI(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})

	t.Run("invalid_json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.discoverJWKSURI(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse discovery document")
	})

	t.Run("missing_jwks_uri", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"issuer": "https://example.com",
			})
		}))
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		_, err := provider.discoverJWKSURI(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing jwks_uri")
	})
}

func TestFetchJWKS_Metrics(t *testing.T) {
	rsaKey := createTestRSAKey(t)
	server := createMockJWKSServer(t, &rsaKey.PublicKey, "metrics-kid")

	m := &mockMetrics{}
	provider := NewDefaultKeyProvider(server.URL, server.Client(), m)

	_, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
	require.NoError(t, err)

	m.mu.Lock()
	defer m.mu.Unlock()
	require.NotEmpty(t, m.opCounts)
	lastCount := m.opCounts[len(m.opCounts)-1]
	assert.Equal(t, "fetch_jwks", lastCount.operation)
	assert.Equal(t, "OK", lastCount.status)
}

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
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

	provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

func TestNewKeyProviderWithJWKSURI(t *testing.T) {
	rsaKey := createTestRSAKey(t)
	kid := "override-kid"

	var jwksHits, discoveryHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksHits.Add(1)
		jwk := jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		discoveryHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	provider := NewKeyProviderWithJWKSURI(server.URL+"/openid/v1/jwks", server.Client(), nil)
	ctx := context.Background()

	t.Run("fetches_from_override_without_discovery", func(t *testing.T) {
		key, err := provider.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.IsType(t, &rsa.PublicKey{}, key)
		assert.Equal(t, int64(1), jwksHits.Load())
		assert.Equal(t, int64(0), discoveryHits.Load(), "override must skip OIDC discovery")
	})

	t.Run("cache_hit_skips_refetch", func(t *testing.T) {
		jwksHits.Store(0)
		_, err := provider.GetKey(ctx, kid)
		require.NoError(t, err)
		assert.Equal(t, int64(0), jwksHits.Load())
	})
}

func TestFetchJWKS(t *testing.T) {
	t.Run("valid_rsa_key", func(t *testing.T) {
		rsaKey := createTestRSAKey(t)
		server := createMockJWKSServer(t, &rsaKey.PublicKey, "rsa-kid")
		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))

		keys, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.IsType(t, &rsa.PublicKey{}, keys["rsa-kid"])
	})

	t.Run("valid_ecdsa_key", func(t *testing.T) {
		ecKey := createTestECDSAKey(t)
		server := createMockJWKSServer(t, &ecKey.PublicKey, "ec-kid")
		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))

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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
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

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
		_, err := provider.discoverJWKSURI(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing jwks_uri")
	})
}

func TestFetchJWKS_Metrics(t *testing.T) {
	rsaKey := createTestRSAKey(t)
	server := createMockJWKSServer(t, &rsaKey.PublicKey, "metrics-kid")

	m := &mockMetrics{}
	provider := NewDefaultKeyProvider(server.URL, server.Client(), m, WithAllowHTTP(true))

	_, err := provider.fetchJWKS(context.Background(), server.URL+"/.well-known/jwks")
	require.NoError(t, err)

	m.mu.Lock()
	defer m.mu.Unlock()
	require.NotEmpty(t, m.opCounts)
	lastCount := m.opCounts[len(m.opCounts)-1]
	assert.Equal(t, "fetch_jwks", lastCount.operation)
	assert.Equal(t, "OK", lastCount.status)
}

// A discovery document is remote input. These assert that what it says about
// where the keys live is checked before the keys are fetched from there --
// which is the whole value of authenticating the document in the first place.
func TestDiscoveredJWKSURIScheme(t *testing.T) {
	// discoveryServing returns a mock issuer whose discovery document advertises
	// the given jwks_uri verbatim.
	discoveryServing := func(jwksURI string) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"jwks_uri": jwksURI})
		})
		return httptest.NewServer(mux)
	}

	t.Run("plaintext_jwks_uri_is_refused", func(t *testing.T) {
		server := discoveryServing("http://attacker.example/keys")
		defer server.Close()

		// allowHTTP covers reaching the mock ISSUER over http; it is deliberately
		// not set, so the jwks_uri is judged by the strict rule.
		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil)
		provider.allowHTTP = false
		_, err := provider.discoverJWKSURI(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unusable jwks_uri")
		assert.Contains(t, err.Error(), "scheme must be https")
	})

	t.Run("https_jwks_uri_on_another_host_is_accepted", func(t *testing.T) {
		// Not a same-host rule. Where the keys live is an address; when the
		// transport is authenticated, what answers there is decided by the
		// authenticated identity, not by the hostname matching.
		server := discoveryServing("https://keys.example/keys")
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
		uri, err := provider.discoverJWKSURI(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "https://keys.example/keys", uri)
	})

	t.Run("https_jwks_uri_with_a_query_is_accepted", func(t *testing.T) {
		// Azure AD B2C publishes exactly this shape. A check borrowed from the
		// issuer rules would reject it, so this pins that it is a transport
		// check and not an issuer-shape check.
		server := discoveryServing("https://login.example/discovery/v2.0/keys?p=b2c_1_signupsignin")
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
		uri, err := provider.discoverJWKSURI(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "https://login.example/discovery/v2.0/keys?p=b2c_1_signupsignin", uri)
	})

	t.Run("plaintext_jwks_uri_is_allowed_when_opted_in", func(t *testing.T) {
		server := discoveryServing("http://mock.example/keys")
		defer server.Close()

		provider := NewDefaultKeyProvider(server.URL, server.Client(), nil, WithAllowHTTP(true))
		uri, err := provider.discoverJWKSURI(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "http://mock.example/keys", uri)
	})
}

// A scheme check made when the URL is read is advisory unless the redirect that
// walks around it is refused too.
func TestRefuseDowngrade(t *testing.T) {
	t.Run("https_to_http_is_refused", func(t *testing.T) {
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer plain.Close()

		tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/keys", http.StatusFound)
		}))
		defer tls.Close()

		client := refuseDowngrade(tls.Client())
		_, err := client.Get(tls.URL + "/keys")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be downgraded")
	})

	t.Run("https_to_https_is_followed", func(t *testing.T) {
		final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("keys"))
		}))
		defer final.Close()

		first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL+"/keys", http.StatusFound)
		}))
		defer first.Close()

		// One client that trusts both test CAs, so the redirect is refused for
		// the scheme or not at all.
		pool := x509.NewCertPool()
		pool.AddCert(first.Certificate())
		pool.AddCert(final.Certificate())
		client := refuseDowngrade(&http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		})

		resp, err := client.Get(first.URL + "/keys")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("a_caller_policy_still_runs", func(t *testing.T) {
		called := false
		client := refuseDowngrade(&http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				called = true
				return nil
			},
		})
		require.NotNil(t, client.CheckRedirect)
		req, err := http.NewRequest(http.MethodGet, "https://example.com/", nil)
		require.NoError(t, err)
		via, err := http.NewRequest(http.MethodGet, "https://example.com/first", nil)
		require.NoError(t, err)
		require.NoError(t, client.CheckRedirect(req, []*http.Request{via}))
		assert.True(t, called, "refuseDowngrade must not discard a policy the caller already set")
	})
}

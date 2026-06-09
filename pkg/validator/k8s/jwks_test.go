package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverClusterIssuer(t *testing.T) {
	t.Run("valid_issuer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, oidcDiscoveryPath, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"issuer": "https://kubernetes.default.svc",
			})
		}))
		defer server.Close()

		issuer, err := discoverClusterIssuer(context.Background(), server.Client(), server.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://kubernetes.default.svc", issuer)
	})

	t.Run("non_200_response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
		}))
		defer server.Close()

		_, err := discoverClusterIssuer(context.Background(), server.Client(), server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 403")
	})

	t.Run("invalid_json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		_, err := discoverClusterIssuer(context.Background(), server.Client(), server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse discovery document")
	})

	t.Run("missing_issuer", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": "https://example.com/jwks",
			})
		}))
		defer server.Close()

		_, err := discoverClusterIssuer(context.Background(), server.Client(), server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing issuer")
	})
}

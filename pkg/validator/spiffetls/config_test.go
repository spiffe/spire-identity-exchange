package spiffetls

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSocketPath(t *testing.T) {
	tests := []struct {
		name        string
		pluginLevel string
		serverLevel string
		expect      string
	}{
		{
			name:        "plugin_level_wins",
			pluginLevel: "/plugin.sock",
			serverLevel: "/server.sock",
			expect:      "/plugin.sock",
		},
		{
			name:        "falls_back_to_server_level",
			serverLevel: "/server.sock",
			expect:      "/server.sock",
		},
		{
			name:        "plugin_level_alone",
			pluginLevel: "/plugin.sock",
			expect:      "/plugin.sock",
		},
		{
			name:   "both_empty",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, ResolveSocketPath(tt.pluginLevel, tt.serverLevel))
		})
	}
}

func TestValidateDiscoverySPIFFEID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		expectErr bool
		errMsg    string
	}{
		{
			name: "empty_is_allowed",
			id:   "",
		},
		{
			name: "valid_id",
			id:   "spiffe://example.org/oidc-discovery-provider",
		},
		{
			name:      "not_a_spiffe_id",
			id:        "https://example.org/oidc",
			expectErr: true,
			errMsg:    "invalid discoverySPIFFEID",
		},
		{
			// Parses cleanly but would authorize no real workload, so it is
			// rejected here rather than failing silently at handshake time.
			name:      "trust_domain_only_needs_a_path",
			id:        "spiffe://example.org",
			expectErr: true,
			errMsg:    "must include a path",
		},
		{
			name:      "garbage",
			id:        "not a url at all",
			expectErr: true,
			errMsg:    "invalid discoverySPIFFEID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDiscoverySPIFFEID(tt.id)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthorizerFor(t *testing.T) {
	const (
		wantedID = "spiffe://example.org/oidc-discovery-provider"
		otherID  = "spiffe://example.org/something-else"
		otherTD  = "spiffe://other.org/oidc-discovery-provider"
	)

	t.Run("exact_id_wins_over_trust_domain", func(t *testing.T) {
		// Both are configured. The exact ID is narrower and must be the one
		// applied: a different workload in the same trust domain is rejected.
		auth, err := AuthorizerFor(wantedID, "example.org")
		require.NoError(t, err)

		assert.NoError(t, auth(spiffeid.RequireFromString(wantedID), nil))
		assert.Error(t, auth(spiffeid.RequireFromString(otherID), nil),
			"a trust-domain peer that is not the configured ID must be rejected")
	})

	t.Run("trust_domain_when_no_id", func(t *testing.T) {
		auth, err := AuthorizerFor("", "example.org")
		require.NoError(t, err)

		assert.NoError(t, auth(spiffeid.RequireFromString(otherID), nil))
		assert.Error(t, auth(spiffeid.RequireFromString(otherTD), nil),
			"a peer outside the trust domain must be rejected")
	})

	t.Run("id_alone_needs_no_trust_domain", func(t *testing.T) {
		auth, err := AuthorizerFor(wantedID, "")
		require.NoError(t, err)

		assert.NoError(t, auth(spiffeid.RequireFromString(wantedID), nil))
		assert.Error(t, auth(spiffeid.RequireFromString(otherID), nil))
	})

	t.Run("neither_configured_is_an_error", func(t *testing.T) {
		_, err := AuthorizerFor("", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no discovery SPIFFE ID or trust domain")
	})

	t.Run("malformed_id", func(t *testing.T) {
		_, err := AuthorizerFor("https://example.org/oidc", "example.org")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid discoverySPIFFEID")
	})

	t.Run("malformed_trust_domain", func(t *testing.T) {
		_, err := AuthorizerFor("", "not a trust domain")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid trust domain")
	})
}

func TestNewTrustBundleHTTPClient_Guards(t *testing.T) {
	auth, err := AuthorizerFor("spiffe://example.org/x", "")
	require.NoError(t, err)

	t.Run("empty_socket_path", func(t *testing.T) {
		_, err := NewTrustBundleHTTPClient("", auth, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "socket path must not be empty")
	})

	t.Run("nil_authorizer", func(t *testing.T) {
		_, err := NewTrustBundleHTTPClient("/some.sock", nil, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorizer must not be nil")
	})
}

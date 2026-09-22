package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
    "github.com/spiffe/spire-identity-exchange/pkg/validator"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.yaml.in/yaml/v3"
)

func TestConfig_Unmarshal(t *testing.T) {
    t.Run("valid config", func(t *testing.T) {
        raw := `issuerURL: "https://issuer.example.org"
audiences: ["spire-server"]
trustDomain: "example.org"
pathPatterns: ["^/workload/.*"]`
        var node yaml.Node
        require.NoError(t, yaml.Unmarshal([]byte(raw), &node))
        cfg := new(Config)
        require.NoError(t, cfg.Unmarshal(&node))
        assert.Equal(t, "https://issuer.example.org", cfg.IssuerURL)
        assert.Equal(t, []string{"spire-server"}, cfg.Audiences)
        assert.Equal(t, "example.org", cfg.TrustDomain)
        assert.Equal(t, []string{"^/workload/.*"}, cfg.PathPatterns)
    })

    t.Run("workload_api config fields", func(t *testing.T) {
        raw := `issuerURL: "https://issuer.example.org"
audiences: ["spire-server"]
trustDomain: "example.org"
pathPatterns: ["^/workload/.*"]
keySource: workload_api
jwksTrustDomain: "peer.example.org"
agentWorkloadSocketPath: /tmp/agent.sock`
        var node yaml.Node
        require.NoError(t, yaml.Unmarshal([]byte(raw), &node))
        cfg := new(Config)
        require.NoError(t, cfg.Unmarshal(&node))
        assert.Equal(t, KeySourceWorkloadAPI, cfg.KeySource)
        assert.Equal(t, "peer.example.org", cfg.JWKSTrustDomain)
        assert.Equal(t, "/tmp/agent.sock", cfg.AgentWorkloadSocketPath)
        assert.NoError(t, cfg.ValidateConfig())
    })

    t.Run("empty config", func(t *testing.T) {
        raw := `{}`
        var node yaml.Node
        require.NoError(t, yaml.Unmarshal([]byte(raw), &node))
        cfg := new(Config)
        err := cfg.Unmarshal(&node)
        // Fields will be empty; this is allowed in Unmarshal
        assert.NoError(t, err)
        assert.ErrorContains(t, cfg.ValidateConfig(), "issuer URL must not be empty")
    })
}

func TestConfig_ValidateConfig(t *testing.T) {
    cases := []struct {
        name        string
        mutateCfg   func(*Config)
        expectError string
    }{
        {
            name: "valid minimal config",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "",
        },
        {
            name: "empty issuer URL",
            mutateCfg: func(cfg *Config) {
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "issuer URL must not be empty",
        },
        {
            // With a discoveryURL the issuer is only compared against the `iss`
            // claim, so its scheme is not constrained.
            name: "http issuer URL with https discovery URL is accepted",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "http://issuer.example.org"
                cfg.DiscoveryURL = "https://discovery.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "",
        },
        {
            // Without one, the issuer is what gets fetched and inherits the
            // scheme requirement.
            name: "http issuer URL without discovery URL is rejected",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "http://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "invalid issuer URL: scheme must be https",
        },
        {
            name: "malformed issuer URL",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org?foo=bar"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "query parameters are not allowed",
        },
        {
            // The discovery URL is dereferenced, so it must be https.
            name: "http discovery URL is rejected",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.DiscoveryURL = "http://discovery.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "invalid discovery URL: scheme must be https",
        },
        {
            name: "discovery SPIFFE ID with plugin socket",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.DiscoverySPIFFEID = "spiffe://example.org/oidc-discovery-provider"
                cfg.AgentWorkloadSocketPath = "/plugin.sock"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "",
        },
        {
            // connectWithTrustBundle alone still works; it just authorizes any
            // member of the trust domain rather than one identity.
            name: "connectWithTrustBundle with plugin socket",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.ConnectWithTrustBundle = true
                cfg.AgentWorkloadSocketPath = "/plugin.sock"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "",
        },
        {
            name: "malformed discovery SPIFFE ID",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.DiscoverySPIFFEID = "https://example.org/oidc"
                cfg.AgentWorkloadSocketPath = "/plugin.sock"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "invalid discoverySPIFFEID",
        },
        {
            name: "discovery SPIFFE ID without any socket",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.DiscoverySPIFFEID = "spiffe://example.org/oidc-discovery-provider"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "workload API socket path must be available",
        },
        {
            name: "empty trust domain",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "trust domain must not be empty",
        },
        {
            name: "empty path patterns",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
            },
            expectError: "at least one path pattern must be specified",
        },
        {
            name: "empty audiences",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "at least one audience must be specified",
        },
        {
            name: "workload_api requires socket path",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.KeySource = KeySourceWorkloadAPI
            },
            expectError: "a workload API socket path must be available when keySource is workload_api",
        },
        {
            // The server-level spire.agentWorkloadSocketPath reaches the plugin
            // through validator.WorkloadAPIDefaulter, so it satisfies this the
            // same way it satisfies connectWithTrustBundle.
            name: "workload_api accepts the server-level socket path",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.KeySource = KeySourceWorkloadAPI
                cfg.SetDefaultWorkloadAPISocketPath("/run/spire/agent.sock")
            },
            expectError: "",
        },
        {
            name: "workload_api conflicts with connectWithTrustBundle",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.KeySource = KeySourceWorkloadAPI
                cfg.ConnectWithTrustBundle = true
                cfg.AgentWorkloadSocketPath = "/tmp/agent.sock"
            },
            expectError: "connectWithTrustBundle cannot be used with keySource workload_api",
        },
        {
            name: "invalid keySource",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.KeySource = "invalid"
            },
            expectError: "unsupported keySource",
        },
        {
            name: "valid workload_api config",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.KeySource = KeySourceWorkloadAPI
                cfg.AgentWorkloadSocketPath = "/tmp/agent.sock"
                cfg.JWKSTrustDomain = "peer.example.org"
            },
            expectError: "",
        },
        {
            name: "invalid jwksTrustDomain",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "https://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
                cfg.JWKSTrustDomain = "not a valid trust domain"
            },
            expectError: "invalid jwksTrustDomain",
        },
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            cfg := &Config{}
            tc.mutateCfg(cfg)
            err := cfg.ValidateConfig()
            if tc.expectError == "" {
                assert.NoError(t, err)
            } else {
                assert.ErrorContains(t, err, tc.expectError)
            }
        })
    }
}

func TestValidate(t *testing.T) {
    // Build a test token validator with a simple key (this test focuses on the
    // spiffe-specific validation logic, not JWT crypto). In practice, the shared
    // jwt.Validator handles key management via JWKS.

    // Valid trust domain and path pattern
    cfg := Config{
        IssuerURL:   "https://issuer.example.org",
        Audiences:   []string{"spire-server"},
        TrustDomain: "example.org",
        PathPatterns: []string{
            "^/workload/.*",
            "^/app/v1/.*",
        },
    }
    v, err := NewValidator(cfg)
    require.NoError(t, err)

    t.Run("valid SPIFFE SVID token", func(t *testing.T) {
        raw := map[string]interface{}{
            "sub": "spiffe://example.org/workload/myapp",
        }
        err := v.checkAllowLists(raw)
        assert.NoError(t, err)
    })

    t.Run("missing sub claim", func(t *testing.T) {
        raw := map[string]interface{}{
            "iss": "https://issuer.example.org",
        }
        err := v.checkAllowLists(raw)
        assert.ErrorContains(t, err, "token is missing required 'sub' claim")
    })

    t.Run("sub not a string", func(t *testing.T) {
        raw := map[string]interface{}{
            "sub": 12345,
        }
        err := v.checkAllowLists(raw)
        assert.ErrorContains(t, err, "token 'sub' claim must be a string")
    })

    t.Run("invalid SPIFFE ID format", func(t *testing.T) {
        raw := map[string]interface{}{
            "sub": "not-a-spiffe-id",
        }
        err := v.checkAllowLists(raw)
        assert.ErrorContains(t, err, "failed to parse SPIFFE ID from 'sub'")
    })

    t.Run("trust domain mismatch", func(t *testing.T) {
        raw := map[string]interface{}{
            "sub": "spiffe://other.org/workload/myapp",
        }
        err := v.checkAllowLists(raw)
        assert.ErrorContains(t, err, "does not match configured trust domain")
    })

    t.Run("path does not match patterns", func(t *testing.T) {
        raw := map[string]interface{}{
            "sub": "spiffe://example.org/otherpath/myapp",
        }
        err := v.checkAllowLists(raw)
        assert.ErrorContains(t, err, "does not match any allowed path patterns")
    })

    t.Run("valid with URL-encoded path", func(t *testing.T) {
        // SPIFFE IDs may have encoded segments that need to be decoded
        raw := map[string]interface{}{
            "sub": "spiffe://example.org/workload/v2/foo",
        }
        err := v.checkAllowLists(raw)
        assert.NoError(t, err)
    })

    t.Run("trust domain parse error", func(t *testing.T) {
        cfg := Config{
            IssuerURL:   "https://issuer.example.org",
            Audiences:   []string{"spire-server"},
            TrustDomain: " not-a-valid-trust-domain ",
            PathPatterns: []string{"^/workload/.*"},
        }
        _, err := NewValidator(cfg)
        assert.ErrorContains(t, err, "invalid trust domain")
    })
}

func TestGenerateSelectors(t *testing.T) {
    cfg := Config{
        IssuerURL:   "https://issuer.example.org",
        Audiences:   []string{"spire-server"},
        TrustDomain: "example.org",
        PathPatterns: []string{"^/workload/.*"},
    }
    v, err := NewValidator(cfg)
    require.NoError(t, err)

    // Create mock claims with a sub claim
    raw := map[string]interface{}{
        "sub": "spiffe://example.org/workload/myapp/production",
    }
    claims := &validator.JWTClaims{
        Raw: raw,
    }

    selectors := v.GenerateSelectors(claims)

    require.NotNil(t, selectors)
    assert.Contains(t, selectors, &types.Selector{Type: "spiffe", Value: "source_trust_domain:example.org"})
    assert.Contains(t, selectors, &types.Selector{Type: "spiffe", Value: "source_path:/workload/myapp/production"})
    assert.Contains(t, selectors, &types.Selector{Type: "spiffe", Value: "source_spiffe_id:spiffe://example.org/workload/myapp/production"})
}

type keySyncSpy struct {
	started bool
}

func (s *keySyncSpy) Start(context.Context) error {
	s.started = true
	return nil
}

func TestValidator_Start(t *testing.T) {
	syncer := &keySyncSpy{}
	v := &Validator{keySync: syncer}
	require.NoError(t, v.Start(context.Background()))
	assert.True(t, syncer.started)

	v = &Validator{}
	require.NoError(t, v.Start(context.Background()))
}

func TestTokenValidatorLoader(t *testing.T) {
    loader, err := TokenValidatorLoaderGenerator()
    require.NoError(t, err)
    assert.NotNil(t, loader)

    // verify it's a *Config
    _, ok := loader.(*Config)
    assert.True(t, ok)

    // validate config fields can be unmarshaled
    raw := `issuerURL: "https://issuer.example.org"
audiences: ["spire-server"]
trustDomain: "example.org"
pathPatterns: ["^/app/.*"]`
    var node yaml.Node
    require.NoError(t, yaml.Unmarshal([]byte(raw), &node))
    require.NoError(t, loader.Unmarshal(&node))
    assert.NoError(t, loader.ValidateConfig()) // should pass validation

    // Test NewValidator path
    validator, err := loader.NewValidator()
    assert.NoError(t, err)
    assert.NotNil(t, validator)
}

// Reaching this fetch through NewValidator needs a live SPIFFE Workload API, so
// these drive the function directly.
func TestDiscoverJWKSURI(t *testing.T) {
	// discoveryServer answers the well-known path with whatever handler is given
	// and returns a client configured to trust it.
	discoveryServer := func(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client) {
		t.Helper()
		srv := httptest.NewTLSServer(h)
		t.Cleanup(srv.Close)
		return srv, srv.Client()
	}

	t.Run("refuses an https discovery URL that redirects to plaintext", func(t *testing.T) {
		// An attacker-controlled hop. If the redirect were followed, the document
		// naming the signing keys would arrive over a connection nothing
		// authenticated -- and every scheme check here would be advisory.
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"jwks_uri":"https://attacker.example.org/keys"}`)
		}))
		defer plain.Close()

		srv, client := discoveryServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL, http.StatusFound)
		})

		_, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not be downgraded")
	})

	// The negative above proves nothing on its own: a fetch that failed for any
	// reason would also error. This is the control.
	t.Run("follows a redirect that stays on https", func(t *testing.T) {
		final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"jwks_uri":"https://issuer.example.org/keys"}`)
		}))
		defer final.Close()

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL, http.StatusFound)
		}))
		defer srv.Close()

		// One client that trusts both hops; each httptest server signs with its own.
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		pool.AddCert(final.Certificate())
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		}

		uri, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.org/keys", uri)
	})

	t.Run("returns the advertised jwks_uri", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, oidcDiscoveryPath, r.URL.Path)
			fmt.Fprint(w, `{"jwks_uri":"https://issuer.example.org/keys"}`)
		})
		uri, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example.org/keys", uri)
	})

	t.Run("rejects a plaintext jwks_uri", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"jwks_uri":"http://issuer.example.org/keys"}`)
		})
		_, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unusable jwks_uri")
	})

	t.Run("accepts a plaintext jwks_uri when allowHTTP is set", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"jwks_uri":"http://issuer.example.org/keys"}`)
		})
		uri, err := discoverJWKSURI(context.Background(), client, srv.URL, true)
		require.NoError(t, err)
		assert.Equal(t, "http://issuer.example.org/keys", uri)
	})

	t.Run("rejects a document with no jwks_uri", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `{"issuer":"https://issuer.example.org"}`)
		})
		_, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing jwks_uri")
	})

	t.Run("reports a non-200", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "nope")
		})
		_, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})

	t.Run("reports an unparseable document", func(t *testing.T) {
		srv, client := discoveryServer(t, func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "not json")
		})
		_, err := discoverJWKSURI(context.Background(), client, srv.URL, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse discovery document")
	})
}

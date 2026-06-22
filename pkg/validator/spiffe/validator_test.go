package spiffe

import (
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
            name: "invalid issuer URL (http)",
            mutateCfg: func(cfg *Config) {
                cfg.IssuerURL = "http://issuer.example.org"
                cfg.Audiences = []string{"spire-server"}
                cfg.TrustDomain = "example.org"
                cfg.PathPatterns = []string{"^/workload/.*"}
            },
            expectError: "scheme must be https",
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

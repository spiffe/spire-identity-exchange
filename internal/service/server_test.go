package service

import (
	"testing"
	"time"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func TestServer_NewGRPCHandler_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
			SVIDTTL:     config.Duration(time.Hour),
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/github/{{.org}}/{{.repo}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Equal(t, mockValidator, handler.githubOIDC.validator)
	assert.Equal(t, mockSpireClient, handler.spireClient)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, "example.org", handler.trustDomain.String())
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestServer_NewGRPCHandler_SimpleTemplate(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "test.domain",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://test.domain/simple",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Equal(t, "test.domain", handler.trustDomain.String())
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestServer_NewGRPCHandler_ComplexTemplate(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/{{.TrustDomain}}/github/{{.org}}/{{.repo}}/{{.ref}}/{{.sha}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestServer_NewGRPCHandler_InvalidTemplate_MissingClosingBrace(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "{{invalid",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid SPIFFE ID template")
}

func TestServer_NewGRPCHandler_InvalidTemplate_UnterminatedAction(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/{{.repo",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid SPIFFE ID template")
}

func TestServer_NewGRPCHandler_InvalidTemplate_BadSyntax(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/{{if}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid SPIFFE ID template")
}

func TestServer_NewGRPCHandler_InvalidTrustDomain_WithSpaces(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "invalid trust domain",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid spire.trustDomain")
}

func TestServer_NewGRPCHandler_InvalidTrustDomain_Empty(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid spire.trustDomain")
}

func TestServer_NewGRPCHandler_InvalidTrustDomain_WithScheme(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "spiffe://example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	// spiffeid.TrustDomainFromString accepts the scheme and parses out the domain.
	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	// It should succeed and extract the domain part
	require.NoError(t, err)
	assert.NotNil(t, handler)
	// The trust domain will be parsed from the spiffe:// URL
	assert.Contains(t, handler.trustDomain.String(), "example.org")
}

func TestServer_NewGRPCHandler_AllFieldsSet(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		Server: config.ServerConfig{
			Port: 8443,
			TLS: config.TLSConfig{
				CertFile: "/path/to/cert",
				KeyFile:  "/path/to/key",
			},
		},
		SPIRE: config.SPIREConfig{
			TrustDomain:    "my-trust-domain.com",
			UnixSocketPath: "/tmp/spire.sock",
			SVIDTTL:        config.Duration(2 * time.Hour),
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			Issuer:           "https://issuer.example.com",
			Audiences:        []string{"aud1", "aud2"},
			SPIFFEIDTemplate: "spiffe://my-trust-domain.com/workload/{{.id}}",
			Enabled:          true,
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)

	// Verify all fields are properly set
	assert.Equal(t, mockValidator, handler.githubOIDC.validator)
	assert.Equal(t, mockSpireClient, handler.spireClient)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, "my-trust-domain.com", handler.trustDomain.String())
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)

	// Verify the config is fully accessible
	assert.Equal(t, 8443, handler.config.Server.Port)
	assert.Equal(t, config.Duration(2*time.Hour), handler.config.SPIRE.SVIDTTL)
	assert.Equal(t, "https://issuer.example.com", handler.config.GitHubOIDC.Issuer)
}

func TestServer_NewGRPCHandler_NilValidator(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockSpireClient := &MockServerClient{}

	// Should succeed even with nil validator (though it may not be useful)
	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, nil, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.githubOIDC)
}

func TestServer_NewGRPCHandler_NilSpireClient(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}

	// Should succeed even with nil SPIRE client (though it may not be useful)
	handler, err := NewGRPCHandler(nil, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.spireClient)
}

func TestServer_NewGRPCHandler_NilLogger(t *testing.T) {
	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	// Should succeed even with nil logger (though it may not be useful)
	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, nil)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Nil(t, handler.logger)
}

func TestServer_NewGRPCHandler_TemplateWithConditionals(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/{{if .org}}{{.org}}{{else}}default{{end}}/{{.repo}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestServer_NewGRPCHandler_TemplateWithFunctions(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			// Using built-in template functions
			SPIFFEIDTemplate: "spiffe://example.org/{{.org | print}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestServer_NewGRPCHandler_MultilineTrustDomain(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "multi\nline",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid spire.trustDomain")
}

func TestServer_NewGRPCHandler_SubdomainTrustDomain(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "subdomain.example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://subdomain.example.org/workload",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Equal(t, "subdomain.example.org", handler.trustDomain.String())
}

func TestServer_NewGRPCHandler_DifferentTrustDomainFormats(t *testing.T) {
	testCases := []struct {
		name        string
		trustDomain string
		shouldError bool
	}{
		{
			name:        "Simple domain",
			trustDomain: "example.org",
			shouldError: false,
		},
		{
			name:        "Subdomain",
			trustDomain: "test.example.org",
			shouldError: false,
		},
		{
			name:        "With dash",
			trustDomain: "my-domain.org",
			shouldError: false,
		},
		{
			name:        "With underscore",
			trustDomain: "my_domain.org",
			shouldError: false,
		},
		{
			name:        "Localhost",
			trustDomain: "localhost",
			shouldError: false,
		},
		{
			name:        "With port",
			trustDomain: "example.org:8080",
			shouldError: true,
		},
		{
			name:        "With path",
			trustDomain: "example.org/path",
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := zaptest.NewLogger(t)

			cfg := &config.SpireIdentityExchangeConfig{
				SPIRE: config.SPIREConfig{
					TrustDomain: tc.trustDomain,
				},
				GitHubOIDC: config.GitHubOIDCConfig{
					SPIFFEIDTemplate: "spiffe://example.org/test",
				},
			}

			mockValidator := &MockValidator{}
			mockSpireClient := &MockServerClient{}

			handler, err := NewGRPCHandler(mockSpireClient, nil, cfg, mockValidator, nil, nil, logger)
			if tc.shouldError {
				assert.Error(t, err, "Expected error for trust domain: %s", tc.trustDomain)
				assert.Nil(t, handler)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, handler)
				assert.Equal(t, tc.trustDomain, handler.trustDomain.String())
			}
		})
	}
}

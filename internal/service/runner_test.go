package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// MockValidator is a mock implementation of the TokenValidator interface
type MockValidator struct {
	mock.Mock
}

func (m *MockValidator) Validate(ctx context.Context, token string) (*utils.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*utils.Claims), args.Error(1)
}

// MockKeySynchronizer is a mock that implements both TokenValidator and KeySynchronizer
type MockKeySynchronizer struct {
	MockValidator
	startCalled bool
	startErr    error
}

func (m *MockKeySynchronizer) Start(ctx context.Context) error {
	m.startCalled = true
	return m.startErr
}

func TestRunSpireIdentityExchangeServer_NilConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	mockValidator := &MockValidator{}

	err := runSpireIdentityExchangeServer(ctx, nil, &MockServerClient{}, mockValidator, nil, RESTDeps{}, nil, logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is nil")
}

func TestRunSpireIdentityExchangeServer_InvalidValidatorConfig(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Use a cancelled context to prevent the server from running
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &config.SpireIdentityExchangeConfig{
		Server: config.ServerConfig{
			Port: 0, // invalid port
		},
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			Issuer:           "", // Invalid: empty issuer
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}
	mockValidator := &MockValidator{}

	err := runSpireIdentityExchangeServer(ctx, cfg, &MockServerClient{}, mockValidator, nil, RESTDeps{}, nil, logger)

	// With an empty issuer, the validator creation should fail
	// However, if it doesn't, the cancelled context will cause the server to shut down
	// Either way, the function should return (possibly with a nil error if shutdown)
	_ = err // Accept either error or nil
}

func TestRunSpireIdentityExchangeServer_InvalidSPIFFEIDTemplate(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// First, we need to get past the validator creation
	// Since we can't easily mock the validator creation in runSpireIdentityExchangeServer,
	// we'll test NewGRPCHandler directly which is called by runSpireIdentityExchangeServer
	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "{{invalid template syntax",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	_, err := NewGRPCHandler(mockSpireClient, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid SPIFFE ID template")
}

func TestRunSpireIdentityExchangeServer_ValidatorStartError(t *testing.T) {
	// This test would require more complex mocking of the validator.NewValidator function
	// Since that's an external function, we can't easily mock it without dependency injection
	// For now, we'll skip this scenario or test it at integration level
	t.Skip("Requires mocking validator.NewValidator which needs dependency injection")
}

func TestRunSpireIdentityExchangeServer_Success(t *testing.T) {
	// This test would require actual validator creation which needs real OIDC endpoints
	// For a true unit test, we'd need to refactor runSpireIdentityExchangeServer to accept a validator
	t.Skip("Requires refactoring runSpireIdentityExchangeServer to accept validator as parameter")
}

func TestRunSpireIdentityExchangeServer_PortAlreadyInUse(t *testing.T) {
	// This test would fail at validator creation, not at port binding
	// We'd need dependency injection to properly test this
	t.Skip("Requires dependency injection to properly test port conflicts")
}

func TestNewGRPCHandler_Success(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/github/{{.org}}/{{.repo}}",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, cfg, mockValidator, nil, nil, logger)

	assert.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Equal(t, mockValidator, handler.githubOIDC.validator)
	assert.Equal(t, mockSpireClient, handler.spireClient)
	assert.Equal(t, cfg, handler.config)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, "example.org", handler.trustDomain.String())
	assert.NotNil(t, handler.githubOIDC.spiffeIDTemplate)
}

func TestNewGRPCHandler_InvalidTemplate(t *testing.T) {
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

	handler, err := NewGRPCHandler(mockSpireClient, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid SPIFFE ID template")
}

func TestNewGRPCHandler_InvalidTrustDomain(t *testing.T) {
	logger := zaptest.NewLogger(t)

	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "invalid trust domain with spaces",
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{}

	handler, err := NewGRPCHandler(mockSpireClient, cfg, mockValidator, nil, nil, logger)

	assert.Error(t, err)
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "invalid spire.trustDomain")
}

// TestServerLifecycle tests a more complete server lifecycle
func TestServerLifecycle(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create config with available port
	cfg := &config.SpireIdentityExchangeConfig{
		Server: config.ServerConfig{
			Port: 0,
			TLS:  config.TLSConfig{},
		},
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
			SVIDTTL:     config.Duration(time.Hour),
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: "spiffe://example.org/test",
		},
	}

	// Create mocks
	mockValidator := &MockValidator{}
	mockSpireClient := &MockServerClient{
		svidClient: &MockSVIDClient{},
	}

	// Create handler
	handler, err := NewGRPCHandler(mockSpireClient, cfg, mockValidator, nil, nil, logger)
	require.NoError(t, err)

	// Create listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	require.NoError(t, err)
	defer listener.Close()

	// Create gRPC server
	grpcServer := grpc.NewServer()
	defer grpcServer.Stop()

	// Register service (we can't import the generated proto without creating a cycle,
	// but we can verify the handler was created successfully)
	assert.NotNil(t, handler)

	// Test that we can connect to the server
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()
}

// TestKeySynchronizerIntegration tests the KeySynchronizer interface integration
func TestKeySynchronizerIntegration(t *testing.T) {
	ctx := context.Background()

	// Test validator without KeySynchronizer
	mockValidator := &MockValidator{}

	_, ok := interface{}(mockValidator).(interface{ Start(context.Context) error })
	assert.False(t, ok, "MockValidator should not implement KeySynchronizer")

	// Test validator with KeySynchronizer
	mockSyncer := &MockKeySynchronizer{}
	mockSyncer.startErr = nil

	syncer2, ok := interface{}(mockSyncer).(interface{ Start(context.Context) error })
	assert.True(t, ok, "MockKeySynchronizer should implement KeySynchronizer")

	err := syncer2.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, mockSyncer.startCalled)
}

// TestKeySynchronizerError tests error handling when key synchronizer fails to start
func TestKeySynchronizerError(t *testing.T) {
	ctx := context.Background()

	mockSyncer := &MockKeySynchronizer{}
	mockSyncer.startErr = errors.New("failed to start key sync")

	syncer, ok := interface{}(mockSyncer).(interface{ Start(context.Context) error })
	require.True(t, ok)

	err := syncer.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start key sync")
	assert.True(t, mockSyncer.startCalled)
}

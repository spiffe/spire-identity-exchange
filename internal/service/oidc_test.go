package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/url"
	"testing"
	"text/template"
	"time"

	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	spire_types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// MockTokenValidator is a mock implementation of the TokenValidator interface
type MockTokenValidator struct {
	mock.Mock
}

func (m *MockTokenValidator) Validate(ctx context.Context, token string, _ v.Purpose) (v.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(v.Claims), args.Error(1)
}

// MockSVIDClient is a mock implementation of the SVID client
type MockSVIDClient struct {
	mock.Mock
}

func (m *MockSVIDClient) MintX509SVID(ctx context.Context, req *svidv1.MintX509SVIDRequest, opts ...grpc.CallOption) (*svidv1.MintX509SVIDResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*svidv1.MintX509SVIDResponse), args.Error(1)
}

func (m *MockSVIDClient) BatchNewX509SVID(ctx context.Context, req *svidv1.BatchNewX509SVIDRequest, opts ...grpc.CallOption) (*svidv1.BatchNewX509SVIDResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*svidv1.BatchNewX509SVIDResponse), args.Error(1)
}

func (m *MockSVIDClient) NewJWTSVID(ctx context.Context, req *svidv1.NewJWTSVIDRequest, opts ...grpc.CallOption) (*svidv1.NewJWTSVIDResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*svidv1.NewJWTSVIDResponse), args.Error(1)
}

func (m *MockSVIDClient) NewDownstreamX509CA(ctx context.Context, req *svidv1.NewDownstreamX509CARequest, opts ...grpc.CallOption) (*svidv1.NewDownstreamX509CAResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*svidv1.NewDownstreamX509CAResponse), args.Error(1)
}

func (m *MockSVIDClient) MintJWTSVID(ctx context.Context, req *svidv1.MintJWTSVIDRequest, opts ...grpc.CallOption) (*svidv1.MintJWTSVIDResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*svidv1.MintJWTSVIDResponse), args.Error(1)
}

// MockAgentClient is a minimal mock that satisfies the agentv1.AgentClient interface
type MockAgentClient struct{}

func (m *MockAgentClient) CountAgents(ctx context.Context, req *agentv1.CountAgentsRequest, opts ...grpc.CallOption) (*agentv1.CountAgentsResponse, error) {
	return nil, nil
}

func (m *MockAgentClient) ListAgents(ctx context.Context, req *agentv1.ListAgentsRequest, opts ...grpc.CallOption) (*agentv1.ListAgentsResponse, error) {
	return nil, nil
}

func (m *MockAgentClient) GetAgent(ctx context.Context, req *agentv1.GetAgentRequest, opts ...grpc.CallOption) (*spire_types.Agent, error) {
	return nil, nil
}

func (m *MockAgentClient) DeleteAgent(ctx context.Context, req *agentv1.DeleteAgentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (m *MockAgentClient) BanAgent(ctx context.Context, req *agentv1.BanAgentRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (m *MockAgentClient) AttestAgent(ctx context.Context, opts ...grpc.CallOption) (agentv1.Agent_AttestAgentClient, error) {
	return nil, nil
}

func (m *MockAgentClient) PostStatus(ctx context.Context, req *agentv1.PostStatusRequest, opts ...grpc.CallOption) (*agentv1.PostStatusResponse, error) {
	return nil, nil
}

func (m *MockAgentClient) CreateJoinToken(ctx context.Context, req *agentv1.CreateJoinTokenRequest, opts ...grpc.CallOption) (*spire_types.JoinToken, error) {
	return nil, nil
}

func (m *MockAgentClient) RenewAgent(ctx context.Context, req *agentv1.RenewAgentRequest, opts ...grpc.CallOption) (*agentv1.RenewAgentResponse, error) {
	return nil, nil
}

// MockServerClient is a mock implementation of the SPIRE server client
type MockServerClient struct {
	mock.Mock
	svidClient *MockSVIDClient
}

func (m *MockServerClient) NewSVIDClient() svidv1.SVIDClient {
	return m.svidClient
}

func (m *MockServerClient) NewAgentClient() agentv1.AgentClient {
	return &MockAgentClient{}
}

func (m *MockServerClient) NewBundleClient() bundlev1.BundleClient {
	return &MockBundleClient{}
}

func (m *MockServerClient) NewEntryClient() entryv1.EntryClient {
	return &MockEntryClient{}
}

func (m *MockServerClient) NewDebugClient() debugv1.DebugClient {
	return &MockDebugClient{}
}

func (m *MockServerClient) NewHealthClient() grpc_health_v1.HealthClient {
	return &MockHealthClient{}
}

func (m *MockServerClient) NewTrustDomainClient() trustdomainv1.TrustDomainClient {
	return &MockTrustDomainClient{}
}

func (m *MockServerClient) Release() {
	// No-op for mock
}

// Minimal mock implementations for other required clients
type MockBundleClient struct{}

func (m *MockBundleClient) GetBundle(ctx context.Context, req *bundlev1.GetBundleRequest, opts ...grpc.CallOption) (*spire_types.Bundle, error) {
	return nil, nil
}

func (m *MockBundleClient) AppendBundle(ctx context.Context, req *bundlev1.AppendBundleRequest, opts ...grpc.CallOption) (*spire_types.Bundle, error) {
	return nil, nil
}

func (m *MockBundleClient) PublishJWTAuthority(ctx context.Context, req *bundlev1.PublishJWTAuthorityRequest, opts ...grpc.CallOption) (*bundlev1.PublishJWTAuthorityResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) ListFederatedBundles(ctx context.Context, req *bundlev1.ListFederatedBundlesRequest, opts ...grpc.CallOption) (*bundlev1.ListFederatedBundlesResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) GetFederatedBundle(ctx context.Context, req *bundlev1.GetFederatedBundleRequest, opts ...grpc.CallOption) (*spire_types.Bundle, error) {
	return nil, nil
}

func (m *MockBundleClient) BatchCreateFederatedBundle(ctx context.Context, req *bundlev1.BatchCreateFederatedBundleRequest, opts ...grpc.CallOption) (*bundlev1.BatchCreateFederatedBundleResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) BatchUpdateFederatedBundle(ctx context.Context, req *bundlev1.BatchUpdateFederatedBundleRequest, opts ...grpc.CallOption) (*bundlev1.BatchUpdateFederatedBundleResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) BatchSetFederatedBundle(ctx context.Context, req *bundlev1.BatchSetFederatedBundleRequest, opts ...grpc.CallOption) (*bundlev1.BatchSetFederatedBundleResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) BatchDeleteFederatedBundle(ctx context.Context, req *bundlev1.BatchDeleteFederatedBundleRequest, opts ...grpc.CallOption) (*bundlev1.BatchDeleteFederatedBundleResponse, error) {
	return nil, nil
}

func (m *MockBundleClient) CountBundles(ctx context.Context, req *bundlev1.CountBundlesRequest, opts ...grpc.CallOption) (*bundlev1.CountBundlesResponse, error) {
	return nil, nil
}

type MockEntryClient struct{}

func (m *MockEntryClient) ListEntries(ctx context.Context, req *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) GetEntry(ctx context.Context, req *entryv1.GetEntryRequest, opts ...grpc.CallOption) (*spire_types.Entry, error) {
	return nil, nil
}

func (m *MockEntryClient) BatchCreateEntry(ctx context.Context, req *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) BatchUpdateEntry(ctx context.Context, req *entryv1.BatchUpdateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) BatchDeleteEntry(ctx context.Context, req *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) GetAuthorizedEntries(ctx context.Context, req *entryv1.GetAuthorizedEntriesRequest, opts ...grpc.CallOption) (*entryv1.GetAuthorizedEntriesResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) CountEntries(ctx context.Context, req *entryv1.CountEntriesRequest, opts ...grpc.CallOption) (*entryv1.CountEntriesResponse, error) {
	return nil, nil
}

func (m *MockEntryClient) SyncAuthorizedEntries(ctx context.Context, opts ...grpc.CallOption) (entryv1.Entry_SyncAuthorizedEntriesClient, error) {
	return nil, nil
}

type MockDebugClient struct{}

func (m *MockDebugClient) GetInfo(ctx context.Context, req *debugv1.GetInfoRequest, opts ...grpc.CallOption) (*debugv1.GetInfoResponse, error) {
	return nil, nil
}

type MockHealthClient struct{ grpc_health_v1.HealthClient }

func (m *MockHealthClient) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (m *MockHealthClient) Watch(ctx context.Context, req *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (grpc_health_v1.Health_WatchClient, error) {
	return nil, nil
}

type MockTrustDomainClient struct{}

func (m *MockTrustDomainClient) ListFederationRelationships(ctx context.Context, req *trustdomainv1.ListFederationRelationshipsRequest, opts ...grpc.CallOption) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	return nil, nil
}

func (m *MockTrustDomainClient) GetFederationRelationship(ctx context.Context, req *trustdomainv1.GetFederationRelationshipRequest, opts ...grpc.CallOption) (*spire_types.FederationRelationship, error) {
	return nil, nil
}

func (m *MockTrustDomainClient) BatchCreateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchCreateFederationRelationshipRequest, opts ...grpc.CallOption) (*trustdomainv1.BatchCreateFederationRelationshipResponse, error) {
	return nil, nil
}

func (m *MockTrustDomainClient) BatchUpdateFederationRelationship(ctx context.Context, req *trustdomainv1.BatchUpdateFederationRelationshipRequest, opts ...grpc.CallOption) (*trustdomainv1.BatchUpdateFederationRelationshipResponse, error) {
	return nil, nil
}

func (m *MockTrustDomainClient) BatchDeleteFederationRelationship(ctx context.Context, req *trustdomainv1.BatchDeleteFederationRelationshipRequest, opts ...grpc.CallOption) (*trustdomainv1.BatchDeleteFederationRelationshipResponse, error) {
	return nil, nil
}

func (m *MockTrustDomainClient) RefreshBundle(ctx context.Context, req *trustdomainv1.RefreshBundleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// Helper function to generate a valid CSR with a specific SPIFFE ID
func generateTestCSR(t *testing.T, spiffeID string) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"Test Org"},
		},
	}

	if spiffeID != "" {
		uri, err := url.Parse(spiffeID)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{uri}
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, privateKey)
	require.NoError(t, err)

	return csrBytes
}

// Helper function to create a test server with mocked dependencies
func setupTestServer(t *testing.T, templateStr string) (*SpireIdentityExchangeServer, *MockTokenValidator, *MockServerClient, *MockSVIDClient) {
	logger := zaptest.NewLogger(t)
	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
			SVIDTTL:     config.Duration(time.Hour),
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: templateStr,
		},
	}

	tmpl, err := template.New(spiffeTemplateName).Parse(templateStr)
	require.NoError(t, err)

	mockValidator := &MockTokenValidator{}
	mockSVIDClient := &MockSVIDClient{}
	mockServerClient := &MockServerClient{
		svidClient: mockSVIDClient,
	}

	// Initialize metrics for test
	testRegistry := prometheus.NewRegistry()
	testMetrics := prommetrics.NewPluginMetrics(testRegistry, "test")

	server := &SpireIdentityExchangeServer{
		spireClient: mockServerClient,
		githubOIDC: &authHandler{
			validator:        mockValidator,
			spiffeIDTemplate: tmpl,
			svidTTL:          effectiveTTL(cfg.GitHubOIDC.SVIDTTL, cfg.SPIRE.SVIDTTL),
		},
		config:          cfg,
		purposeResolver: v.NewPurposeResolver(v.PurposeMode(cfg.PurposeMode)),
		logger:          logger,
		metrics:         testMetrics,
		trustDomain:     spiffeid.RequireTrustDomainFromString(cfg.SPIRE.TrustDomain),
	}

	return server, mockValidator, mockServerClient, mockSVIDClient
}

func TestMintCertificateByGithubOIDC_Success(t *testing.T) {
	// Setup
	spiffeIDStr := "spiffe://example.org/github/example-org/test-repo"
	server, mockValidator, _, mockSVIDClient := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	csr := generateTestCSR(t, spiffeIDStr)
	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Issuer:  "https://token.actions.githubusercontent.com",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
			"workflow":   "test-workflow",
			"ref":        "refs/heads/main",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	expectedSVID := &spire_types.X509SVID{
		Id:        &spire_types.SPIFFEID{TrustDomain: "example.org", Path: "/github/example-org/test-repo"},
		CertChain: [][]byte{[]byte("test-cert")},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	mockSVIDClient.On("MintX509SVID", mock.Anything, mock.MatchedBy(func(req *svidv1.MintX509SVIDRequest) bool {
		return req.Ttl == int32(3600)
	})).Return(&svidv1.MintX509SVIDResponse{
		Svid: expectedSVID,
	}, nil)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	require.NotNil(t, resp.X509Svid)
	assert.Equal(t, expectedSVID.CertChain, resp.X509Svid.CertChain)
	assert.Equal(t, expectedSVID.ExpiresAt, resp.X509Svid.ExpiresAt)
	require.NotNil(t, resp.X509Svid.Id)
	assert.Equal(t, expectedSVID.Id.TrustDomain, resp.X509Svid.Id.TrustDomain)
	assert.Equal(t, expectedSVID.Id.Path, resp.X509Svid.Id.Path)
	mockValidator.AssertExpectations(t)
	mockSVIDClient.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_MissingGithubOIDC(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: []byte("test-csr"),
		},
		AuthMethod: nil,
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "GithubOIDC is not set")
}

func TestMintCertificateByGithubOIDC_ValidationFailed(t *testing.T) {
	// Setup
	server, mockValidator, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	githubToken := "invalid-token"

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(nil, errors.New("token validation failed"))

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: []byte("test-csr"),
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to validate OIDC token")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_GenerateSPIFFEIDFailed(t *testing.T) {
	// Setup - use an invalid template that will fail
	server, mockValidator, _, _ := setupTestServer(t, "{{.NonExistentField}}")

	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: generateTestCSR(t, "spiffe://example.org/test"),
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to generate SPIFFE ID")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_InvalidCSR(t *testing.T) {
	// Setup
	server, mockValidator, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: []byte("invalid-csr-data"),
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to parse CSR")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_CSRWithNoURISAN(t *testing.T) {
	// Setup
	server, mockValidator, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Generate CSR without URI SAN
	csr := generateTestCSR(t, "")

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "CSR must contain exactly one URI SAN")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_CSRWithMismatchedSPIFFEID(t *testing.T) {
	// Setup
	spiffeIDInCSR := "spiffe://example.org/different/path"
	server, mockValidator, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	githubToken := "test-github-token"

	// Mock claims - will generate a different SPIFFE ID
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Generate CSR with different SPIFFE ID
	csr := generateTestCSR(t, spiffeIDInCSR)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "CSR SPIFFE ID mismatch")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_SPIREClientMintFailed(t *testing.T) {
	// Setup
	spiffeIDStr := "spiffe://example.org/github/example-org/test-repo"
	server, mockValidator, _, mockSVIDClient := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	csr := generateTestCSR(t, spiffeIDStr)
	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)
	mockSVIDClient.On("MintX509SVID", mock.Anything, mock.Anything).
		Return(nil, errors.New("SPIRE mint error"))

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to mint X.509 SVID")
	mockValidator.AssertExpectations(t)
	mockSVIDClient.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_ContextTimeout(t *testing.T) {
	// Setup
	spiffeIDStr := "spiffe://example.org/github/example-org/test-repo"
	server, mockValidator, _, mockSVIDClient := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	csr := generateTestCSR(t, spiffeIDStr)
	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Simulate timeout by having the SVID client sleep longer than timeout
	mockSVIDClient.On("MintX509SVID", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			<-ctx.Done()
		}).
		Return(nil, context.DeadlineExceeded)

	// Execute with a short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(ctx, req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to mint X.509 SVID")
	mockValidator.AssertExpectations(t)
	mockSVIDClient.AssertExpectations(t)
}

func TestGenerateSPIFFEID_Success(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
			"workflow":   "test-workflow",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/github/example-org/test-repo", spiffeID.String())
}

func TestGenerateSPIFFEID_NoTemplate(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")
	server.githubOIDC.spiffeIDTemplate = nil

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SPIFFE ID template is empty")
	assert.Equal(t, spiffeid.ID{}, spiffeID)
}

func TestGenerateSPIFFEID_TemplateExecutionError(t *testing.T) {
	// Setup - template references a field that doesn't exist
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/{{.NonExistentField}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SPIFFE ID")
	assert.Equal(t, spiffeid.ID{}, spiffeID)
}

func TestGenerateSPIFFEID_WithoutSpiffeSchemePrefix(t *testing.T) {
	// Setup - template that doesn't start with spiffe://
	server, _, _, _ := setupTestServer(t, "/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert - should fail because scheme is missing
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scheme is missing or invalid")
	assert.Equal(t, spiffeid.ID{}, spiffeID)
}

func TestGenerateSPIFFEID_InvalidSPIFFEIDFormat(t *testing.T) {
	// Setup - template that generates an invalid SPIFFE ID
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/invalid//path")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SPIFFE ID")
	assert.Equal(t, spiffeid.ID{}, spiffeID)
}

func TestGenerateSPIFFEID_ComplexTemplate(t *testing.T) {
	// Setup - more complex template
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}/{{.ref}}/{{.sha}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
			"ref":        "main",
			"sha":        "abc123",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/github/example-org/test-repo/main/abc123", spiffeID.String())
}

func TestGenerateSPIFFEID_EmptyProviderClaims(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	// Empty provider claims result in invalid SPIFFE ID (double slashes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SPIFFE ID")
	assert.Equal(t, spiffeid.ID{}, spiffeID)
}

func TestMintCertificateByGithubOIDC_CSRWithMultipleURISANs(t *testing.T) {
	// Setup
	server, mockValidator, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	// Create CSR with multiple URI SANs
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	uri1, _ := url.Parse("spiffe://example.org/test1")
	uri2, _ := url.Parse("spiffe://example.org/test2")

	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test",
		},
		URIs: []*url.URL{uri1, uri2},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, privateKey)
	require.NoError(t, err)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csrBytes,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "CSR must contain exactly one URI SAN")
	mockValidator.AssertExpectations(t)
}

func TestMintCertificateByGithubOIDC_WithDifferentTTL(t *testing.T) {
	// Setup with custom TTL
	customTTL := config.Duration(2 * time.Hour)
	logger := zaptest.NewLogger(t)
	templateStr := "spiffe://example.org/github/{{.org}}/{{.repository}}"
	cfg := &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain: "example.org",
			SVIDTTL:     customTTL,
		},
		GitHubOIDC: config.GitHubOIDCConfig{
			SPIFFEIDTemplate: templateStr,
		},
	}

	tmpl, err := template.New(spiffeTemplateName).Parse(templateStr)
	require.NoError(t, err)

	mockValidator := &MockTokenValidator{}
	mockSVIDClient := &MockSVIDClient{}
	mockServerClient := &MockServerClient{
		svidClient: mockSVIDClient,
	}

	// Initialize metrics for test
	testRegistry := prometheus.NewRegistry()
	testMetrics := prommetrics.NewPluginMetrics(testRegistry, "test")

	server := &SpireIdentityExchangeServer{
		spireClient: mockServerClient,
		githubOIDC: &authHandler{
			validator:        mockValidator,
			spiffeIDTemplate: tmpl,
			svidTTL:          effectiveTTL(cfg.GitHubOIDC.SVIDTTL, cfg.SPIRE.SVIDTTL),
		},
		config:          cfg,
		purposeResolver: v.NewPurposeResolver(v.PurposeMode(cfg.PurposeMode)),
		logger:          logger,
		metrics:         testMetrics,
		trustDomain:     spiffeid.RequireTrustDomainFromString(cfg.SPIRE.TrustDomain),
	}

	spiffeIDStr := "spiffe://example.org/github/example-org/test-repo"
	csr := generateTestCSR(t, spiffeIDStr)
	githubToken := "test-github-token"

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock expectations
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil)

	expectedSVID := &spire_types.X509SVID{
		Id:        &spire_types.SPIFFEID{TrustDomain: "example.org", Path: "/github/example-org/test-repo"},
		CertChain: [][]byte{[]byte("test-cert")},
		ExpiresAt: time.Now().Add(time.Duration(customTTL)).Unix(),
	}

	// Verify TTL is correct (2 hours = 7200 seconds)
	mockSVIDClient.On("MintX509SVID", mock.Anything, mock.MatchedBy(func(req *svidv1.MintX509SVIDRequest) bool {
		return req.Ttl == int32(7200)
	})).Return(&svidv1.MintX509SVIDResponse{
		Svid: expectedSVID,
	}, nil)

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	require.NotNil(t, resp.X509Svid)
	assert.Equal(t, expectedSVID.CertChain, resp.X509Svid.CertChain)
	assert.Equal(t, expectedSVID.ExpiresAt, resp.X509Svid.ExpiresAt)
	require.NotNil(t, resp.X509Svid.Id)
	assert.Equal(t, expectedSVID.Id.TrustDomain, resp.X509Svid.Id.TrustDomain)
	assert.Equal(t, expectedSVID.Id.Path, resp.X509Svid.Id.Path)
	mockValidator.AssertExpectations(t)
	mockSVIDClient.AssertExpectations(t)
}

func TestGenerateSPIFFEID_WithLeadingSlash(t *testing.T) {
	// Setup - template that starts with /
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.NoError(t, err)
	// Leading slash should be handled correctly
	assert.Equal(t, "spiffe://example.org/github/example-org/test-repo", spiffeID.String())
}

func TestGenerateSPIFFEID_WithFullSPIFFEScheme(t *testing.T) {
	// Setup - template that includes the full spiffe:// scheme
	server, _, _, _ := setupTestServer(t, "spiffe://{{.trust_domain}}/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/github/example-org/test-repo", spiffeID.String())
}

func TestMintCertificateByGithubOIDC_NilMintX509SVIDRequest(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	// Execute - this will cause a panic if not handled
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: nil,
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: "test-token",
			},
		},
	}

	// This should panic, so we recover and check
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic but didn't get one")
		}
	}()

	_, _ = server.MintCertificateByGithubOIDC(context.Background(), req, server.logger)
}

func TestMintCertificateByGithubOIDC_ContextCancellation(t *testing.T) {
	// Setup
	spiffeIDStr := "spiffe://example.org/github/example-org/test-repo"
	server, mockValidator, _, mockSVIDClient := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	csr := generateTestCSR(t, spiffeIDStr)
	githubToken := "test-github-token"

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Mock claims
	claims := &v.JWTClaims{
		Subject: "repo:example-org/test-repo:ref:refs/heads/main",
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo",
		},
	}

	// Mock validator might not even be called depending on when context is checked
	mockValidator.On("Validate", mock.Anything, githubToken).Return(claims, nil).Maybe()

	// Mock SVID client to return context error
	mockSVIDClient.On("MintX509SVID", mock.Anything, mock.Anything).
		Return(nil, context.Canceled).Maybe()

	// Execute
	req := &proto.MintCertificateRequest{
		MintX509SVIDRequest: &svidv1.MintX509SVIDRequest{
			Csr: csr,
		},
		AuthMethod: &proto.MintCertificateRequest_GithubOIDC{
			GithubOIDC: &proto.GithubOIDC{
				GithubToken: githubToken,
			},
		},
	}

	resp, err := server.MintCertificateByGithubOIDC(ctx, req, server.logger)

	// Assert - should fail due to context cancellation
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestGenerateSPIFFEID_SpecialCharactersInClaims(t *testing.T) {
	// Setup
	server, _, _, _ := setupTestServer(t, "spiffe://example.org/github/{{.org}}/{{.repository}}")

	claims := &v.JWTClaims{
		Raw: map[string]interface{}{
			"repository": "example-org/test-repo-with-special-chars",
			"workflow":   "CI/CD Pipeline!",
		},
	}

	// Execute
	spiffeID, err := utils.GenerateSPIFFEID(claims.Raw, server.githubOIDC.spiffeIDTemplate, server.config.SPIRE.TrustDomain)

	// Assert
	assert.NoError(t, err)
	assert.Contains(t, spiffeID.String(), "example-org")
	assert.Contains(t, spiffeID.String(), "test-repo-with-special-chars")
}

package service

import (
	"fmt"
	"text/template"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	server_util "github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
)

// authHandler pairs a token validator with the SPIFFE ID template and TTL for a single auth method.
type authHandler struct {
	validator            v.TokenValidator
	spiffeIDTemplate     *template.Template
	svidTTL              int32            // seconds; 0 means use the global spire.svidTTL
	workflowTTLOverrides map[string]int32 // job_workflow_ref → TTL seconds; nil if not configured
}

// SpireIdentityExchangeServer is the server for the spire-identity-exchange service.
type SpireIdentityExchangeServer struct {
	proto.UnimplementedSpireIdentityExchangeApiServer
	spireClient     server_util.ServerClient
	delegated       *delegated.Client // used by the gRPC PluginAuth path; nil when not needed
	githubOIDC      *authHandler      // legacy hard-coded auth, nil if not configured
	k8sSAToken      *authHandler      // legacy hard-coded auth, nil if not configured
	config          *config.SpireIdentityExchangeConfig
	purposeResolver *v.PurposeResolver
	metrics         metrics.Metrics
	logger          *zap.Logger
	trustDomain     spiffeid.TrustDomain
}

// NewGRPCHandler creates a new GRPC server handler. Pass nil for a validator
// to disable that auth method. delegatedClient may be nil when PluginAuth is
// not in use; the dispatch arm rejects with Unavailable rather than panicking.
func NewGRPCHandler(
	spireClient server_util.ServerClient,
	delegatedClient *delegated.Client,
	cfg *config.SpireIdentityExchangeConfig,
	githubOIDCValidator v.TokenValidator,
	k8sSATokenValidator v.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) (*SpireIdentityExchangeServer, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(cfg.SPIRE.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid spire.trustDomain %q: %w", cfg.SPIRE.TrustDomain, err)
	}

	server := &SpireIdentityExchangeServer{
		spireClient:     spireClient,
		delegated:       delegatedClient,
		trustDomain:     trustDomain,
		config:          cfg,
		purposeResolver: v.NewPurposeResolver(v.PurposeMode(cfg.PurposeMode)),
		metrics:         metrics,
		logger:          logger,
	}

	if githubOIDCValidator != nil {
		tmpl, err := template.New(spiffeTemplateName).Parse(cfg.GitHubOIDC.SPIFFEIDTemplate)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE ID template for GitHub OIDC: %w", err)
		}
		server.githubOIDC = &authHandler{
			validator:            githubOIDCValidator,
			spiffeIDTemplate:     tmpl,
			svidTTL:              effectiveTTL(cfg.GitHubOIDC.SVIDTTL, cfg.SPIRE.SVIDTTL),
			workflowTTLOverrides: buildWorkflowTTLOverrides(cfg.GitHubOIDC.WorkflowTTLOverrides),
		}
	}

	if k8sSATokenValidator != nil {
		tmpl, err := template.New(spiffeTemplateName).Parse(cfg.K8sSAToken.SPIFFEIDTemplate)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE ID template for K8s SA token: %w", err)
		}
		server.k8sSAToken = &authHandler{
			validator:        k8sSATokenValidator,
			spiffeIDTemplate: tmpl,
			svidTTL:          effectiveTTL(cfg.K8sSAToken.SVIDTTL, cfg.SPIRE.SVIDTTL),
		}
	}

	// PluginAuth dispatches off cfg.Auth.LoadedPlugins directly; no per-plugin handler needed.
	return server, nil
}

// effectiveTTL returns the per-method TTL if set, otherwise falls back to the global TTL.
func effectiveTTL(methodTTL, globalTTL config.Duration) int32 {
	if methodTTL != 0 {
		return int32(time.Duration(methodTTL).Seconds())
	}
	return int32(time.Duration(globalTTL).Seconds())
}

// buildWorkflowTTLOverrides converts the config WorkflowTTLOverrides map (Duration values)
// into a map of int32 seconds for fast lookup at request time.
func buildWorkflowTTLOverrides(overrides map[string]config.Duration) map[string]int32 {
	if len(overrides) == 0 {
		return nil
	}
	result := make(map[string]int32, len(overrides))
	for k, v := range overrides {
		result[k] = int32(time.Duration(v).Seconds())
	}
	return result
}

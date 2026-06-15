//go:build legacy

package service

import (
	"fmt"
	"text/template"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// initLegacyAuthHandlers builds the githubOIDC and k8sSAToken auth handlers
// from the supplied validators. A nil validator means the handler stays nil
// and the dispatch in MintCertificate returns Unimplemented for that method.
func (h *SpireIdentityExchangeServer) initLegacyAuthHandlers(cfg *config.SpireIdentityExchangeConfig, githubOIDCValidator, k8sSATokenValidator v.TokenValidator) error {
	if githubOIDCValidator != nil {
		tmpl, err := template.New(spiffeTemplateName).Parse(cfg.GitHubOIDC.SPIFFEIDTemplate)
		if err != nil {
			return fmt.Errorf("invalid SPIFFE ID template for GitHub OIDC: %w", err)
		}
		h.githubOIDC = &authHandler{
			validator:            githubOIDCValidator,
			spiffeIDTemplate:     tmpl,
			svidTTL:              effectiveTTL(cfg.GitHubOIDC.SVIDTTL, cfg.SPIRE.SVIDTTL),
			workflowTTLOverrides: buildWorkflowTTLOverrides(cfg.GitHubOIDC.WorkflowTTLOverrides),
		}
	}

	if k8sSATokenValidator != nil {
		tmpl, err := template.New(spiffeTemplateName).Parse(cfg.K8sSAToken.SPIFFEIDTemplate)
		if err != nil {
			return fmt.Errorf("invalid SPIFFE ID template for K8s SA token: %w", err)
		}
		h.k8sSAToken = &authHandler{
			validator:        k8sSATokenValidator,
			spiffeIDTemplate: tmpl,
			svidTTL:          effectiveTTL(cfg.K8sSAToken.SVIDTTL, cfg.SPIRE.SVIDTTL),
		}
	}

	return nil
}

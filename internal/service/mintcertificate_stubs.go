//go:build !legacy

package service

import (
	"context"
	"text/template"

	proto "github.com/spiffe/spire-identity-exchange/api"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MintCertificateByGithubOIDC returns Unimplemented when the "legacy" build tag is absent.
func (h *SpireIdentityExchangeServer) MintCertificateByGithubOIDC(context.Context, *proto.MintCertificateRequest, *zap.Logger) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GitHub OIDC authentication requires the legacy build tag")
}

// MintCertificateByK8sSAToken returns Unimplemented when the "legacy" build tag is absent.
func (h *SpireIdentityExchangeServer) MintCertificateByK8sSAToken(context.Context, *proto.MintCertificateRequest, *zap.Logger) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "K8s SA token authentication requires the legacy build tag")
}

// mintFromClaims is a no-op stub for the non-legacy build.
func (h *SpireIdentityExchangeServer) mintFromClaims(context.Context, v.Claims, *authHandler, *proto.MintCertificateRequest, *auditEntry) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "legacy mint path not available")
}

// resolveTTL is a no-op stub for the non-legacy build.
func (h *authHandler) resolveTTL(v.Claims) int32 {
	return 0
}

// mintX509SVIDFromClaims is a no-op stub for the non-legacy build.
func (h *SpireIdentityExchangeServer) mintX509SVIDFromClaims(context.Context, v.Claims, *template.Template, []byte, int32, *auditEntry) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "legacy mint path not available")
}

// mintJWTSVIDFromClaims is a no-op stub for the non-legacy build.
func (h *SpireIdentityExchangeServer) mintJWTSVIDFromClaims(context.Context, v.Claims, *template.Template, []string, int32, *auditEntry) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "legacy mint path not available")
}

// mintX509SVIDServerKeyGen is a no-op stub for the non-legacy build.
func (h *SpireIdentityExchangeServer) mintX509SVIDServerKeyGen(context.Context, v.Claims, *template.Template, int32, *auditEntry) (*proto.MintCertificateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "legacy mint path not available")
}

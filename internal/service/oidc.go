package service

import (
	"context"

	proto "github.com/spiffe/spire-identity-exchange/api"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MintCertificate is grpc method that mints a spiffe ID certificate for the given request.
func (h *SpireIdentityExchangeServer) MintCertificate(ctx context.Context, req *proto.MintCertificateRequest) (*proto.MintCertificateResponse, error) {
	var err error
	var response *proto.MintCertificateResponse

	switch req.AuthMethod.(type) {
	case *proto.MintCertificateRequest_GithubOIDC:
		if h.githubOIDC == nil {
			return nil, status.Error(codes.Unimplemented, "GitHub OIDC authentication is not configured")
		}
		response, err = h.MintCertificateByGithubOIDC(ctx, req, h.logger)

	case *proto.MintCertificateRequest_K8SSA:
		if h.k8sSAToken == nil {
			return nil, status.Error(codes.Unimplemented, "Kubernetes SA token authentication is not configured")
		}
		response, err = h.MintCertificateByK8sSAToken(ctx, req, h.logger)

	case *proto.MintCertificateRequest_PluginAuth:
		response, err = h.MintCertificateByPlugin(ctx, req, h.logger)

	default:
		h.logger.Warn("unknown AuthMethod type", zap.Any("AuthMethod", req.AuthMethod))
		return nil, status.Error(codes.InvalidArgument, "unknown AuthMethod type")
	}

	if err != nil {
		h.logger.Error("failed to mint certificate", zap.Error(err))
		return nil, err
	}

	var spiffeID string
	switch {
	case response.X509Svid != nil && response.X509Svid.Id != nil:
		spiffeID = response.X509Svid.Id.String()
	case response.JwtSvid != nil && response.JwtSvid.Id != nil:
		spiffeID = response.JwtSvid.Id.String()
	}
	h.logger.Info("Minted certificate successfully", zap.String("spiffeID", spiffeID))
	return response, nil
}

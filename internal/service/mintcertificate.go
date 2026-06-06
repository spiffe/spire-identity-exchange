package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"text/template"
	"time"

	proto "github.com/spiffe/spire-identity-exchange/api"
	constant "github.com/spiffe/spire-identity-exchange/internal/const"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	spiffeTemplateName = "spiffeid"
	certMintTimeout    = 30 * time.Second
)

// MintCertificateByGithubOIDC mints an SVID using GitHub Actions OIDC token authentication.
func (h *SpireIdentityExchangeServer) MintCertificateByGithubOIDC(ctx context.Context, req *proto.MintCertificateRequest, logger *zap.Logger) (*proto.MintCertificateResponse, error) {
	audit := &auditEntry{AttestorType: "github_oidc"}
	statusCode := codes.InvalidArgument
	now := time.Now()
	defer func() {
		h.metrics.IncOperationCount(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByGithubOIDC, statusCode.String())
		h.metrics.ObserveOperationDuration(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByGithubOIDC, statusCode.String(), time.Since(now).Seconds())
	}()

	githubOIDC := req.GetGithubOIDC()
	if githubOIDC == nil {
		return nil, status.Error(codes.InvalidArgument, "GithubOIDC is not set")
	}

	purpose := determinePurpose(req)
	claims, err := h.githubOIDC.validator.Validate(ctx, githubOIDC.GithubToken, purpose)
	if err != nil {
		audit.FailedStage = stageTokenValidation
		audit.RejectionReason = err.Error()
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to validate OIDC token: %v", err))
	}
	audit.TokenIssuer, _ = claims.GetRaw()["iss"].(string)

	resp, err := h.mintFromClaims(ctx, claims, h.githubOIDC, req, audit)
	if err != nil {
		// Preserve the gRPC code embedded in the error so client-input failures
		// (InvalidArgument) aren't mislabeled as server failures (Internal) in metrics.
		statusCode = status.Code(err)
		// audit.logRejection was already called inside mintFromClaims
		return nil, err
	}

	statusCode = codes.OK
	audit.logSuccess(logger)
	return resp, nil
}

// MintCertificateByK8sSAToken mints an SVID using a Kubernetes service account token.
func (h *SpireIdentityExchangeServer) MintCertificateByK8sSAToken(ctx context.Context, req *proto.MintCertificateRequest, logger *zap.Logger) (*proto.MintCertificateResponse, error) {
	audit := &auditEntry{AttestorType: "k8s_sa_token"}
	statusCode := codes.InvalidArgument
	now := time.Now()
	defer func() {
		h.metrics.IncOperationCount(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByK8sSA, statusCode.String())
		h.metrics.ObserveOperationDuration(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByK8sSA, statusCode.String(), time.Since(now).Seconds())
	}()

	k8sSA := req.GetK8SSA()
	if k8sSA == nil {
		return nil, status.Error(codes.InvalidArgument, "K8sSA is not set")
	}

	purpose := determinePurpose(req)
	claims, err := h.k8sSAToken.validator.Validate(ctx, k8sSA.K8SSAToken, purpose)
	if err != nil {
		audit.FailedStage = stageTokenValidation
		audit.RejectionReason = err.Error()
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to validate K8s SA token: %v", err))
	}
	audit.TokenIssuer, _ = claims.GetRaw()["iss"].(string)

	resp, err := h.mintFromClaims(ctx, claims, h.k8sSAToken, req, audit)
	if err != nil {
		// Preserve the gRPC code embedded in the error so client-input failures
		// (InvalidArgument) aren't mislabeled as server failures (Internal) in metrics.
		statusCode = status.Code(err)
		// audit.logRejection was already called inside mintFromClaims
		return nil, err
	}

	statusCode = codes.OK
	audit.logSuccess(logger)
	return resp, nil
}

// mintFromClaims dispatches to the appropriate minting function based on which SVID
// request field is set in req. Exactly one of mintX509SVIDRequest, mintJWTSVIDRequest,
// or serverKeyGenRequest must be non-nil.
func (h *SpireIdentityExchangeServer) mintFromClaims(
	ctx context.Context,
	claims v.Claims,
	handler *authHandler,
	req *proto.MintCertificateRequest,
	audit *auditEntry,
) (*proto.MintCertificateResponse, error) {
	baseTTL := handler.resolveTTL(claims)

	svidRequestCount := 0
	if req.GetMintX509SVIDRequest() != nil {
		svidRequestCount++
	}
	if req.GetMintJWTSVIDRequest() != nil {
		svidRequestCount++
	}
	if req.GetServerKeyGenRequest() != nil {
		svidRequestCount++
	}
	if svidRequestCount > 1 {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "multiple SVID request fields set: exactly one of mintX509SVIDRequest, mintJWTSVIDRequest, or serverKeyGenRequest must be set"
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}

	switch {
	case req.GetMintX509SVIDRequest() != nil:
		audit.SVIDType = "x509"
		x509Req := req.GetMintX509SVIDRequest()
		ttl := clampRequestedTTL(x509Req.GetTtl(), baseTTL)
		return h.mintX509SVIDFromClaims(ctx, claims, handler.spiffeIDTemplate, x509Req.GetCsr(), ttl, audit)

	case req.GetMintJWTSVIDRequest() != nil:
		audit.SVIDType = "jwt"
		jwtReq := req.GetMintJWTSVIDRequest()
		ttl := clampRequestedTTL(jwtReq.GetTtl(), baseTTL)
		return h.mintJWTSVIDFromClaims(ctx, claims, handler.spiffeIDTemplate, jwtReq.GetAudiences(), ttl, audit)

	case req.GetServerKeyGenRequest() != nil:
		audit.SVIDType = "x509"
		skgReq := req.GetServerKeyGenRequest()
		ttl := clampRequestedTTL(skgReq.GetTtl(), baseTTL)
		return h.mintX509SVIDServerKeyGen(ctx, claims, handler.spiffeIDTemplate, ttl, audit)

	default:
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "no SVID request specified: set one of mintX509SVIDRequest, mintJWTSVIDRequest, or serverKeyGenRequest"
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
}

// clampRequestedTTL bounds a client-supplied TTL by the configured maximum.
// A non-positive requested TTL means "use the configured default". The returned TTL is
// the smaller of (requested, max) so an authenticated workload cannot grant itself a
// longer-lived credential than the operator allows.
func clampRequestedTTL(requested, max int32) int32 {
	if requested <= 0 || requested > max {
		return max
	}
	return requested
}

// resolveTTL returns the SVID TTL for the given claims, applying any per-workflow override.
// For GitHub OIDC requests, if the token's job_workflow_ref matches a key in
// workflowTTLOverrides, that TTL is used instead of the default svidTTL.
func (h *authHandler) resolveTTL(claims v.Claims) int32 {
	if len(h.workflowTTLOverrides) > 0 {
		if wfRef, ok := claims.GetRaw()["job_workflow_ref"].(string); ok && wfRef != "" {
			if ttl, found := h.workflowTTLOverrides[wfRef]; found {
				return ttl
			}
		}
	}
	return h.svidTTL
}

// mintX509SVIDFromClaims generates a SPIFFE ID from claims, validates the client-supplied
// CSR against it, and mints an X.509 SVID via the SPIRE Server API.
func (h *SpireIdentityExchangeServer) mintX509SVIDFromClaims(
	ctx context.Context,
	claims v.Claims,
	tmpl *template.Template,
	csr []byte,
	ttl int32,
	audit *auditEntry,
) (*proto.MintCertificateResponse, error) {
	spiffeID, err := utils.GenerateSPIFFEID(claims.GetRaw(), tmpl, h.config.SPIRE.TrustDomain)
	if err != nil {
		audit.FailedStage = stageSpiffeIDGeneration
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to generate SPIFFE ID: %v", err))
	}
	audit.SpiffeID = spiffeID.String()
	h.logger.Info("Generated SPIFFE ID", zap.String("spiffeID", spiffeID.String()))

	// Validate CSR contains the expected SPIFFE ID URI SAN.
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = fmt.Sprintf("failed to parse CSR: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	if err := parsedCSR.CheckSignature(); err != nil {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = fmt.Sprintf("CSR signature verification failed: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	if len(parsedCSR.URIs) != 1 {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "CSR must contain exactly one URI SAN"
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	csrSpiffeID, err := spiffeid.FromString(parsedCSR.URIs[0].String())
	if err != nil {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = fmt.Sprintf("CSR URI SAN is not a valid SPIFFE ID: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	// SPIFFE ID paths are case-sensitive per the spec, and SPIRE mints the SVID with
	// the exact URI SAN from the supplied CSR. Clients MUST build the CSR using the
	// normalized SPIFFE ID this server derives from the token claims; an exact match
	// is required so the issued SVID matches the identity any other code path (JWT,
	// server-side keygen) would produce for the same workload.
	if spiffeID.TrustDomain() != csrSpiffeID.TrustDomain() || spiffeID.Path() != csrSpiffeID.Path() {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = fmt.Sprintf("CSR SPIFFE ID mismatch: expected %s, got %s", spiffeID, parsedCSR.URIs[0].String())
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}

	mintCtx, cancel := context.WithTimeout(ctx, certMintTimeout)
	defer cancel()
	resp, err := h.spireClient.NewSVIDClient().MintX509SVID(mintCtx, &svidv1.MintX509SVIDRequest{
		Csr: csr,
		Ttl: ttl,
	})
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to mint X.509 SVID: %v", err))
	}

	populateX509AuditFields(audit, resp.Svid)
	return &proto.MintCertificateResponse{X509Svid: resp.Svid}, nil
}

// mintJWTSVIDFromClaims derives the SPIFFE ID from claims and mints a JWT-SVID via
// the SPIRE Server API. No CSR is required.
func (h *SpireIdentityExchangeServer) mintJWTSVIDFromClaims(
	ctx context.Context,
	claims v.Claims,
	tmpl *template.Template,
	audiences []string,
	ttl int32,
	audit *auditEntry,
) (*proto.MintCertificateResponse, error) {
	if len(audiences) == 0 {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "at least one audience is required for JWT-SVID issuance"
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}

	spiffeID, err := utils.GenerateSPIFFEID(claims.GetRaw(), tmpl, h.config.SPIRE.TrustDomain)
	if err != nil {
		audit.FailedStage = stageSpiffeIDGeneration
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to generate SPIFFE ID: %v", err))
	}
	audit.SpiffeID = spiffeID.String()
	h.logger.Info("Generated SPIFFE ID for JWT-SVID", zap.String("spiffeID", spiffeID.String()))

	mintCtx, cancel := context.WithTimeout(ctx, certMintTimeout)
	defer cancel()
	resp, err := h.spireClient.NewSVIDClient().MintJWTSVID(mintCtx, &svidv1.MintJWTSVIDRequest{
		Id: &spiretypes.SPIFFEID{
			TrustDomain: spiffeID.TrustDomain().String(),
			Path:        spiffeID.Path(),
		},
		Audience: audiences,
		Ttl:      ttl,
	})
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to mint JWT-SVID: %v", err))
	}

	if resp.Svid != nil {
		audit.TTLSeconds = resp.Svid.ExpiresAt - time.Now().Unix()
	}
	return &proto.MintCertificateResponse{JwtSvid: resp.Svid}, nil
}

// mintX509SVIDServerKeyGen generates an ECDSA P-256 key pair server-side, builds a
// CSR, mints an X.509 SVID via SPIRE, and returns the certificate chain plus the
// private key. The key is held in memory only for the duration of this call and is
// never stored or logged.
func (h *SpireIdentityExchangeServer) mintX509SVIDServerKeyGen(
	ctx context.Context,
	claims v.Claims,
	tmpl *template.Template,
	ttl int32,
	audit *auditEntry,
) (*proto.MintCertificateResponse, error) {
	spiffeID, err := utils.GenerateSPIFFEID(claims.GetRaw(), tmpl, h.config.SPIRE.TrustDomain)
	if err != nil {
		audit.FailedStage = stageSpiffeIDGeneration
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to generate SPIFFE ID: %v", err))
	}
	audit.SpiffeID = spiffeID.String()
	h.logger.Info("Generated SPIFFE ID for server-side key gen", zap.String("spiffeID", spiffeID.String()))

	// Generate ECDSA P-256 key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("failed to generate key pair: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, audit.RejectionReason)
	}

	// Build CSR with the derived SPIFFE ID as the URI SAN.
	spiffeURI, err := url.Parse(spiffeID.String())
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("failed to parse SPIFFE ID as URL: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, audit.RejectionReason)
	}
	csrTemplate := &x509.CertificateRequest{URIs: []*url.URL{spiffeURI}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("failed to create CSR: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, audit.RejectionReason)
	}

	mintCtx, cancel := context.WithTimeout(ctx, certMintTimeout)
	defer cancel()
	resp, err := h.spireClient.NewSVIDClient().MintX509SVID(mintCtx, &svidv1.MintX509SVIDRequest{
		Csr: csrDER,
		Ttl: ttl,
	})
	if err != nil {
		privKey = nil // discard key material; no partial state is returned
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = err.Error()
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to mint X.509 SVID: %v", err))
	}

	// Marshal private key to PKCS#8 PEM and clear it from memory immediately.
	privKeyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	privKey = nil
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("failed to marshal private key: %v", err)
		audit.logRejection(h.logger)
		return nil, status.Error(codes.Internal, audit.RejectionReason)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyDER})

	populateX509AuditFields(audit, resp.Svid)
	return &proto.MintCertificateResponse{
		X509Svid:      resp.Svid,
		PrivateKeyPem: privKeyPEM,
	}, nil
}

// determinePurpose derives the replay cache Purpose from the mint request.
// JWT-SVID requests include audience-scoped hashing; all others default to X.509.
func determinePurpose(req *proto.MintCertificateRequest) v.Purpose {
	if jwtReq := req.GetMintJWTSVIDRequest(); jwtReq != nil {
		return v.JWTPurpose(jwtReq.GetAudiences())
	}
	return v.X509Purpose()
}

// populateX509AuditFields extracts the serial number and TTL from an X.509 SVID
// response and writes them onto the audit entry.
func populateX509AuditFields(audit *auditEntry, svid *spiretypes.X509SVID) {
	if svid == nil {
		return
	}
	audit.TTLSeconds = svid.ExpiresAt - time.Now().Unix()
	if len(svid.CertChain) > 0 {
		if cert, err := x509.ParseCertificate(svid.CertChain[0]); err == nil {
			audit.SerialNumber = fmt.Sprintf("%X", cert.SerialNumber)
		}
	}
}


package service

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	spiretypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	proto "github.com/spiffe/spire-identity-exchange/api"
	constant "github.com/spiffe/spire-identity-exchange/internal/const"
	configlib "github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	spiffeTemplateName = "spiffeid"
	certMintTimeout    = 30 * time.Second
)

// MintCertificateByPlugin issues an SVID via the SPIRE Agent's Delegated
// Identity API, matching the REST /api/v1/svid/{stack}/x509 path: look up the
// plugin, validate the token, build selectors, fetch the SVID. Identity is
// the entry's SPIFFE ID — no SIE-side template.
//
// Supported SVID-request modes:
//   - serverKeyGenRequest → X.509, agent-generated keypair, PEM key returned.
//   - mintJWTSVIDRequest  → JWT, audiences from the request.
//
// mintX509SVIDRequest is rejected: it's documented as CSR-based ("the private
// key never leaves the client") but the delegated API has no CSR field, so
// honoring it would silently flip the contract and hand the caller a
// server-generated key. Callers wanting X.509 must use serverKeyGenRequest.
//
// The PluginAuth wire shape is a list to reserve room for future stack
// composition (multi-plugin validation in one call). Today the server accepts
// exactly one entry; a multi-entry request returns Unimplemented so the wire
// format is forward-compatible without committing to the semantics yet.
func (h *SpireIdentityExchangeServer) MintCertificateByPlugin(ctx context.Context, req *proto.MintCertificateRequest, logger *zap.Logger) (*proto.MintCertificateResponse, error) {
	pluginAuthList := req.GetPluginAuthList()
	if pluginAuthList == nil {
		return nil, status.Error(codes.InvalidArgument, "PluginAuthList is not set")
	}
	plugins := pluginAuthList.GetPlugins()
	if len(plugins) == 0 {
		return nil, status.Error(codes.InvalidArgument, "pluginAuthList.plugins must contain at least one entry")
	}
	token := ""
	stackName := req.GetStackName()
	if len(plugins) > 1 {
		if stackName == "" {
			return nil, status.Errorf(codes.InvalidArgument, "stack name must be specified when more then one plugin is used")
		}
		sep := ""
		for _, plugin := range plugins {
			pluginName := plugin.GetPluginName()
			if !configlib.PluginNamePattern.MatchString(pluginName) {
				return nil, status.Errorf(codes.InvalidArgument, "plugin name s invalid")
			}
			pt := plugin.GetToken()
			if strings.Contains(pt, ":") {
				return nil, status.Errorf(codes.InvalidArgument, "invalid token")
			}
			token = fmt.Sprintf("%s%s%s=%s", token, sep, pluginName, pt)
			sep = ":"
		}
	} else {
		pluginAuth := plugins[0]
		pluginName := pluginAuth.GetPluginName()
		if stackName == "" {
			stackName = pluginName
		}
		token = pluginAuth.GetToken()
	}
	if stackName == "" {
		return nil, status.Error(codes.InvalidArgument, "stackName is required")
	}

	if h.delegated == nil {
		return nil, status.Error(codes.Unavailable, "delegated identity client is not configured")
	}

	stack, ok := h.config.Auth.LoadedStacks[stackName]
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "unknown stack %q", stackName)
	}

	audit := &auditEntry{AttestorType: stackName}
	statusCode := codes.InvalidArgument
	now := time.Now()
	defer func() {
		// Use a stable operation constant; pluginName goes into audit logs
		// (AttestorType), not metric labels — otherwise unbounded operator-chosen
		// plugin names would explode metric cardinality.
		h.metrics.IncOperationCount(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByPlugin, statusCode.String())
		h.metrics.ObserveOperationDuration(constant.ComponentLabel, constant.PluginLabel, constant.OperationMintCertificateByPlugin, statusCode.String(), time.Since(now).Seconds())
	}()

	purpose := h.determinePurpose(req)
	claims, err := stack.Validate(ctx, token, purpose)
	if err != nil {
		audit.FailedStage = stageTokenValidation
		audit.RejectionReason = err.Error()
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("failed to validate %s token: %v", stackName, err))
	}
	audit.TokenIssuer, _ = claims.GetRaw()["iss"].(string)

	selectors := stack.GenerateSelectors(claims)
	if len(selectors) == 0 {
		audit.FailedStage = stageSelectorGeneration
		audit.RejectionReason = "no selectors derivable from token claims"
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}

	// Detect which SVID request was set. Exactly one of the three SVID-request
	// fields must be set, same invariant as mintFromClaims.
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
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}

	var resp *proto.MintCertificateResponse
	switch {
	case req.GetMintX509SVIDRequest() != nil:
		// mintX509SVIDRequest is documented as CSR-based: "Client generates
		// the key pair and submits a PKCS#10 CSR; the private key never leaves
		// the client." The Delegated Identity API doesn't accept CSRs — the
		// agent always generates the keypair — so this request mode is
		// fundamentally incompatible with the PluginAuth path. Reject every
		// occurrence (CSR populated OR empty) so callers can't accidentally
		// flip the "private key stays with client" guarantee by sending an
		// empty CSR; route them to serverKeyGenRequest, which is the explicit
		// "I want a server-generated key" wire mode.
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "mintX509SVIDRequest is CSR-based and is not supported via PluginAuth; use serverKeyGenRequest for X.509 issuance or mintJWTSVIDRequest for JWT"
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	case req.GetServerKeyGenRequest() != nil:
		audit.SVIDType = "x509"
		resp, err = h.mintPluginX509SVID(ctx, selectors, audit, logger, stackName)
	case req.GetMintJWTSVIDRequest() != nil:
		audit.SVIDType = "jwt"
		resp, err = h.mintPluginJWTSVID(ctx, selectors, req.GetMintJWTSVIDRequest().GetAudiences(), audit, logger, stackName)
	default:
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "no SVID request specified: set one of serverKeyGenRequest or mintJWTSVIDRequest"
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	if err != nil {
		statusCode = status.Code(err)
		return nil, err
	}

	statusCode = codes.OK
	audit.logSuccess(logger)
	return resp, nil
}

// mintPluginX509SVID fetches an X.509 SVID through the Delegated Identity API
// matching the given selectors, and packages it into a MintCertificateResponse.
// The private key is agent-generated (PKCS#8 DER); it is PEM-wrapped before
// being returned in privateKeyPem. audit.SpiffeID is populated on success.
func (h *SpireIdentityExchangeServer) mintPluginX509SVID(ctx context.Context, selectors []*spiretypes.Selector, audit *auditEntry, logger *zap.Logger, pluginName string) (*proto.MintCertificateResponse, error) {
	svid, err := h.delegated.FetchX509SVID(ctx, selectors)
	if err != nil {
		return nil, translateDelegatedFetchError(err, audit, logger, pluginName, "X509")
	}
	id, err := parseSpiffeID(svid.SpiffeID)
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("agent returned invalid SPIFFE ID %q: %v", svid.SpiffeID, err)
		audit.logRejection(logger)
		return nil, status.Error(codes.Internal, "issuance failed")
	}
	audit.SpiffeID = svid.SpiffeID

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: svid.PrivateKey})
	return &proto.MintCertificateResponse{
		X509Svid: &spiretypes.X509SVID{
			CertChain: svid.CertChain,
			Id:        id,
			ExpiresAt: svid.ExpiresAt.Unix(),
			Hint:      svid.Hint,
		},
		PrivateKeyPem: keyPEM,
	}, nil
}

// mintPluginJWTSVID fetches a JWT-SVID through the Delegated Identity API
// matching the given selectors and audiences, and packages it into a
// MintCertificateResponse.
func (h *SpireIdentityExchangeServer) mintPluginJWTSVID(ctx context.Context, selectors []*spiretypes.Selector, audiences []string, audit *auditEntry, logger *zap.Logger, pluginName string) (*proto.MintCertificateResponse, error) {
	if len(audiences) == 0 {
		audit.FailedStage = stageCSRValidation
		audit.RejectionReason = "mintJWTSVIDRequest.audiences must be non-empty"
		audit.logRejection(logger)
		return nil, status.Error(codes.InvalidArgument, audit.RejectionReason)
	}
	svid, err := h.delegated.FetchJWTSVID(ctx, selectors, audiences)
	if err != nil {
		return nil, translateDelegatedFetchError(err, audit, logger, pluginName, "JWT")
	}
	id, err := parseSpiffeID(svid.SpiffeID)
	if err != nil {
		audit.FailedStage = stageSVIDMint
		audit.RejectionReason = fmt.Sprintf("agent returned invalid SPIFFE ID %q: %v", svid.SpiffeID, err)
		audit.logRejection(logger)
		return nil, status.Error(codes.Internal, "issuance failed")
	}
	audit.SpiffeID = svid.SpiffeID

	return &proto.MintCertificateResponse{
		JwtSvid: &spiretypes.JWTSVID{
			Token:     svid.Token,
			Id:        id,
			ExpiresAt: svid.ExpiresAt.Unix(),
			Hint:      svid.Hint,
		},
	}, nil
}

// translateDelegatedFetchError maps the delegated client's sentinel errors to
// gRPC codes, mirroring the REST handler's error mapping at runner.go.
func translateDelegatedFetchError(err error, audit *auditEntry, logger *zap.Logger, pluginName, svidKind string) error {
	audit.FailedStage = stageSVIDMint
	audit.RejectionReason = err.Error()
	switch {
	case errors.Is(err, delegated.ErrNoMatchingEntry):
		logger.Info("no entry matched selectors", zap.String("plugin", pluginName), zap.String("svid_kind", svidKind))
		audit.logRejection(logger)
		return status.Error(codes.NotFound, "no registration entry matches the validated identity")
	case errors.Is(err, delegated.ErrPermissionDenied):
		logger.Error("delegated API rejected this exchange — check authorized_delegates", zap.String("plugin", pluginName), zap.Error(err))
		audit.logRejection(logger)
		return status.Error(codes.Unavailable, "delegated issuance unavailable")
	case errors.Is(err, delegated.ErrUnavailable):
		logger.Error("delegated API unavailable", zap.String("plugin", pluginName), zap.Error(err))
		audit.logRejection(logger)
		return status.Error(codes.Unavailable, "delegated issuance unavailable")
	case errors.Is(err, delegated.ErrInvalidArgument):
		// Agent rejected the selectors as malformed. SIE built them from
		// claims it just validated, so this is a server-side bug.
		logger.Error("delegated API rejected selectors as invalid", zap.String("plugin", pluginName), zap.Error(err))
		audit.logRejection(logger)
		return status.Error(codes.Internal, "issuance failed")
	default:
		logger.Error("delegated svid fetch failed", zap.String("plugin", pluginName), zap.Error(err))
		audit.logRejection(logger)
		return status.Error(codes.Internal, "issuance failed")
	}
}

// parseSpiffeID parses a "spiffe://<td>/<path>" string into the typed proto
// representation expected by spire.api.types.X509SVID / JWTSVID. Uses net/url
// so scheme/host/path extraction follows RFC 3986 rather than hand-rolled
// prefix arithmetic.
func parseSpiffeID(s string) (*spiretypes.SPIFFEID, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "spiffe" {
		return nil, fmt.Errorf("expected spiffe:// scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing trust domain")
	}
	return &spiretypes.SPIFFEID{
		TrustDomain: u.Host,
		Path:        u.Path,
	}, nil
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

// determinePurpose derives the replay cache Purpose from the mint request,
// respecting the configured PurposeMode. In "shared" mode, all requests
// produce the same cache key so a token can only be used once across all
// SVID types.
func (h *SpireIdentityExchangeServer) determinePurpose(req *proto.MintCertificateRequest) v.Purpose {
	if jwtReq := req.GetMintJWTSVIDRequest(); jwtReq != nil {
		return h.purposeResolver.JWT(jwtReq.GetAudiences())
	}
	return h.purposeResolver.X509()
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

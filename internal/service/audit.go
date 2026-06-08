package service

import "go.uber.org/zap"

// Audit stage constants identify the pipeline stage where a request was rejected.
const (
	stageTokenValidation    = "token_validation"
	stageSpiffeIDGeneration = "spiffe_id_generation"
	stageCSRValidation      = "csr_validation"
	stageSVIDMint           = "svid_mint"
)

// auditEntry accumulates structured fields for a single MintCertificate request.
// Call logSuccess or logRejection exactly once at the end of each request.
type auditEntry struct {
	AttestorType string // "github_oidc" or "k8s_psat"
	SVIDType     string // "x509" or "jwt"
	TokenIssuer  string // iss claim value; populated after token validation
	SpiffeID     string // derived SPIFFE ID; populated after SPIFFE ID generation

	// Success-only fields.
	SerialNumber string // hex serial number of the minted leaf cert (X.509 only)
	TTLSeconds   int64  // remaining lifetime in seconds granted by SPIRE

	// Failure-only fields.
	FailedStage     string // stage constant from above
	RejectionReason string // human-readable error message
}

// logSuccess emits a structured audit log line for a successful request.
func (a *auditEntry) logSuccess(logger *zap.Logger) {
	logger.Info("audit",
		zap.String("attestor_type", a.AttestorType),
		zap.String("svid_type", a.SVIDType),
		zap.String("token_issuer", a.TokenIssuer),
		zap.String("spiffe_id", a.SpiffeID),
		zap.String("result", "success"),
		zap.String("serial_number", a.SerialNumber),
		zap.Int64("ttl_seconds", a.TTLSeconds),
	)
}

// logRejection emits a structured audit log line for a rejected request.
func (a *auditEntry) logRejection(logger *zap.Logger) {
	logger.Warn("audit",
		zap.String("attestor_type", a.AttestorType),
		zap.String("svid_type", a.SVIDType),
		zap.String("token_issuer", a.TokenIssuer),
		zap.String("spiffe_id", a.SpiffeID),
		zap.String("result", "rejected"),
		zap.String("failed_stage", a.FailedStage),
		zap.String("rejection_reason", a.RejectionReason),
	)
}

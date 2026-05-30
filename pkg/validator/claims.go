package validator

// Claims is the interface returned by all TokenValidators.
// It provides a common contract for accessing validated token information
// regardless of the underlying token format (JWT, opaque tokens, certificates, etc.).
//
// JWT-based validators should return *JWTClaims which implements this interface.
// Non-JWT validators (e.g., AWS STS, Vault tokens) may implement this interface
// directly with their own concrete type.
type Claims interface {
	// GetRaw returns all claims/attributes as a map for provider-specific access.
	// For JWT tokens, this contains all decoded claims.
	// For non-JWT tokens, this contains attributes obtained from the verification response.
	GetRaw() map[string]interface{}

	// GetUniqueID returns a unique identifier for the token, used for replay detection.
	// For JWT: the "jti" claim (RFC 7519 Section 4.1.7).
	// For non-JWT: a provider-specific unique identifier (e.g., request ID, token accessor).
	GetUniqueID() string

	// GetExpiration returns the token's expiration time as Unix timestamp (seconds).
	// Used by replay caches to determine entry eviction time.
	// Returns 0 if the token has no expiration.
	GetExpiration() int64
}

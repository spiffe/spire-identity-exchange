package validator

// JWTClaims represents validated claims from a JWT-based token.
// Fields correspond to the Registered Claims defined in RFC 7519 Section 4.1.
//
// Implements the Claims interface.
type JWTClaims struct {
	// Issuer identifies the principal that issued the JWT (RFC 7519 Section 4.1.1).
	Issuer string

	// Subject identifies the principal that is the subject of the JWT (RFC 7519 Section 4.1.2).
	Subject string

	// Audience identifies the recipients that the JWT is intended for (RFC 7519 Section 4.1.3).
	Audience []string

	// Expiry is the expiration time (exp) as Unix timestamp in seconds (RFC 7519 Section 4.1.4).
	Expiry int64

	// NotBefore is the time before which the JWT must not be accepted (RFC 7519 Section 4.1.5).
	NotBefore int64

	// IssuedAt is the time at which the JWT was issued (RFC 7519 Section 4.1.6).
	IssuedAt int64

	// JTI is a unique identifier for the JWT, used for replay detection (RFC 7519 Section 4.1.7).
	JTI string

	// Raw contains all claims from the token as a map.
	// This includes both registered and provider-specific claims,
	// enabling flexible access for template execution and selector generation.
	Raw map[string]interface{}
}

// GetRaw returns all claims as a map.
func (c *JWTClaims) GetRaw() map[string]interface{} {
	return c.Raw
}

// GetUniqueID returns the JWT ID (jti) claim.
func (c *JWTClaims) GetUniqueID() string {
	return c.JTI
}

// GetExpiration returns the expiration time as Unix timestamp.
func (c *JWTClaims) GetExpiration() int64 {
	return c.Expiry
}

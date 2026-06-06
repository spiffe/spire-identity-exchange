package validator

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// PurposeMode controls how the replay cache scopes token reuse.
type PurposeMode string

const (
	// PurposeModePurpose allows the same token to be used for different SVID
	// types (e.g. one X.509 and one JWT-SVID). Each purpose gets its own
	// replay cache key.
	PurposeModePurpose PurposeMode = "purpose"

	// PurposeModeShared restricts a token to a single use across all SVID
	// types. The replay cache key is the same regardless of purpose, so a
	// token used for X.509 cannot be reused for JWT-SVID.
	PurposeModeShared PurposeMode = "shared"
)

// Purpose identifies the intended use of a validated token for replay cache
// isolation. Different purposes produce distinct replay cache keys so that
// the same token can be used for multiple SVID types without false replay
// detection. Use the provided constructors (X509Purpose, JWTPurpose,
// SharedPurpose) or a PurposeResolver to create values.
type Purpose struct {
	value string
}

// X509Purpose returns a Purpose for X.509 SVID issuance (including
// server-side key generation).
func X509Purpose() Purpose {
	return Purpose{value: "x509"}
}

// JWTPurpose returns a Purpose for JWT-SVID issuance scoped to the given
// audiences. Audiences are sorted and hashed (SHA-256, full) so the same
// set always produces the same key regardless of caller-supplied order.
func JWTPurpose(audiences []string) Purpose {
	sorted := slices.Clone(audiences)
	slices.Sort(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return Purpose{value: "jwt:" + hex.EncodeToString(h[:])}
}

// SharedPurpose returns a Purpose that produces a single cache key for all
// SVID types. Use this when the deployment requires strict single-use tokens.
func SharedPurpose() Purpose {
	return Purpose{value: "shared"}
}

// PurposeResolver returns the appropriate Purpose for a given request context.
// In "purpose" mode it delegates to the type-specific constructors; in "shared"
// mode it always returns SharedPurpose().
type PurposeResolver struct {
	mode PurposeMode
}

// NewPurposeResolver creates a resolver for the given mode.
// An empty or unrecognized mode defaults to PurposeModeShared.
func NewPurposeResolver(mode PurposeMode) *PurposeResolver {
	if mode != PurposeModePurpose {
		mode = PurposeModeShared
	}
	return &PurposeResolver{mode: mode}
}

// X509 returns the Purpose for X.509 SVID issuance under this resolver's mode.
func (r *PurposeResolver) X509() Purpose {
	if r.mode == PurposeModeShared {
		return SharedPurpose()
	}
	return X509Purpose()
}

// JWT returns the Purpose for JWT-SVID issuance under this resolver's mode.
func (r *PurposeResolver) JWT(audiences []string) Purpose {
	if r.mode == PurposeModeShared {
		return SharedPurpose()
	}
	return JWTPurpose(audiences)
}

// String returns the cache-key fragment for this purpose.
func (p Purpose) String() string {
	return p.value
}

package validator

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Purpose identifies the intended use of a validated token for replay cache
// isolation. Different purposes produce distinct replay cache keys so that
// the same token can be used for multiple SVID types without false replay
// detection. Use the provided constructors (X509Purpose, JWTPurpose) to
// create values.
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
}

// String returns the cache-key fragment for this purpose.
func (p Purpose) String() string {
	return p.value
}

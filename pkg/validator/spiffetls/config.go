package spiffetls

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ResolveSocketPath returns the plugin-level Workload API socket path when it is
// set, falling back to the server-level one. The result may be empty; callers
// decide whether that is an error for their configuration.
func ResolveSocketPath(pluginLevel, serverLevel string) string {
	if pluginLevel != "" {
		return pluginLevel
	}
	return serverLevel
}

// parseDiscoverySPIFFEID parses and sanity-checks a configured discovery
// SPIFFE ID.
func parseDiscoverySPIFFEID(s string) (spiffeid.ID, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid discoverySPIFFEID %q: %w", s, err)
	}
	// A bare trust domain parses cleanly, but no workload SVID carries an empty
	// path, so such a value would authorize nothing -- failing at handshake time
	// with a confusing mismatch rather than here.
	if id.Path() == "" {
		return spiffeid.ID{}, fmt.Errorf("invalid discoverySPIFFEID %q: must include a path, e.g. spiffe://%s/oidc-discovery-provider", s, id.TrustDomain())
	}
	return id, nil
}

// AuthorizerFor returns the Authorizer implied by the configured values.
//
// An exact SPIFFE ID is strictly narrower than trust-domain membership -- both
// are checked against the same URI SAN, not against different fields -- so the
// exact ID wins when both are configured. Pass an empty trustDomain for plugins
// that do not have one.
func AuthorizerFor(discoverySPIFFEID, trustDomain string) (Authorizer, error) {
	if discoverySPIFFEID != "" {
		id, err := parseDiscoverySPIFFEID(discoverySPIFFEID)
		if err != nil {
			return nil, err
		}
		return AuthorizeID(id), nil
	}
	if trustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(trustDomain)
		if err != nil {
			return nil, fmt.Errorf("invalid trust domain %q: %w", trustDomain, err)
		}
		return AuthorizeMemberOf(td), nil
	}
	return nil, fmt.Errorf("no discovery SPIFFE ID or trust domain configured to authorize the endpoint with")
}

// ValidateDiscoverySPIFFEID reports whether a configured discovery SPIFFE ID is
// well formed, so a typo fails at config load rather than at first use.
func ValidateDiscoverySPIFFEID(discoverySPIFFEID string) error {
	if discoverySPIFFEID == "" {
		return nil
	}
	_, err := parseDiscoverySPIFFEID(discoverySPIFFEID)
	return err
}

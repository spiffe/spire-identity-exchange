package spiffe

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// mergedBundleSource unions X.509 authorities from additional trust domains into
// the primary trust domain bundle for SPIFFE TLS verification.
type mergedBundleSource struct {
	inner      x509bundle.Source
	primary    spiffeid.TrustDomain
	additional []spiffeid.TrustDomain
}

func newMergedBundleSource(inner x509bundle.Source, primary spiffeid.TrustDomain, additional []spiffeid.TrustDomain) *mergedBundleSource {
	return &mergedBundleSource{
		inner:      inner,
		primary:    primary,
		additional: additional,
	}
}

func (s *mergedBundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	bundle, err := s.inner.GetX509BundleForTrustDomain(trustDomain)
	if err != nil {
		return nil, err
	}
	if trustDomain.Compare(s.primary) != 0 || len(s.additional) == 0 {
		return bundle, nil
	}

	merged := x509bundle.FromX509Authorities(trustDomain, bundle.X509Authorities())
	for _, td := range s.additional {
		extra, err := s.inner.GetX509BundleForTrustDomain(td)
		if err != nil {
			return nil, fmt.Errorf("failed to get X.509 bundle for merged trust domain %q: %w", td, err)
		}
		for _, authority := range extra.X509Authorities() {
			merged.AddX509Authority(authority)
		}
	}
	return merged, nil
}

func parseMergeTrustDomains(primary string, names []string) ([]spiffeid.TrustDomain, error) {
	if len(names) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{}, len(names)+1)
	seen[primary] = struct{}{}

	out := make([]spiffeid.TrustDomain, 0, len(names))
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("mergeTrustDomains entries must not be empty")
		}
		if _, ok := seen[name]; ok {
			if name == primary {
				return nil, fmt.Errorf("mergeTrustDomains must not include trustDomain %q", primary)
			}
			continue
		}
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return nil, fmt.Errorf("invalid mergeTrustDomains entry %q: %w", name, err)
		}
		seen[name] = struct{}{}
		out = append(out, td)
	}
	return out, nil
}

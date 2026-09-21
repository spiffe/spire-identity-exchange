package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticBundleSource struct {
	bundles map[spiffeid.TrustDomain]*x509bundle.Bundle
}

func (s *staticBundleSource) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	bundle, ok := s.bundles[trustDomain]
	if !ok {
		return nil, fmt.Errorf("no X.509 bundle for trust domain %q", trustDomain)
	}
	return bundle, nil
}

func TestParseMergeTrustDomains(t *testing.T) {
	t.Run("deduplicates entries", func(t *testing.T) {
		tds, err := parseMergeTrustDomains("example.org", []string{"spire-ha", "spire-ha"})
		require.NoError(t, err)
		require.Len(t, tds, 1)
		assert.Equal(t, "spire-ha", tds[0].String())
	})

	t.Run("rejects primary trust domain", func(t *testing.T) {
		_, err := parseMergeTrustDomains("example.org", []string{"example.org"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "must not include trustDomain")
	})

	t.Run("rejects invalid trust domain", func(t *testing.T) {
		_, err := parseMergeTrustDomains("example.org", []string{"not valid"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "invalid mergeTrustDomains entry")
	})
}

func TestMergedBundleSource_GetX509BundleForTrustDomain(t *testing.T) {
	primaryTD := spiffeid.RequireTrustDomainFromString("example.org")
	haTD := spiffeid.RequireTrustDomainFromString("spire-ha")
	otherTD := spiffeid.RequireTrustDomainFromString("partner.org")

	caA, _ := newTestCA(t)
	caB, _ := newTestCA(t)

	inner := &staticBundleSource{
		bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{
			primaryTD: x509bundle.FromX509Authorities(primaryTD, []*x509.Certificate{caA}),
			haTD:      x509bundle.FromX509Authorities(haTD, []*x509.Certificate{caB}),
			otherTD:   x509bundle.New(otherTD),
		},
	}

	merged := newMergedBundleSource(inner, primaryTD, []spiffeid.TrustDomain{haTD})

	t.Run("unions authorities for primary trust domain", func(t *testing.T) {
		bundle, err := merged.GetX509BundleForTrustDomain(primaryTD)
		require.NoError(t, err)
		assert.Len(t, bundle.X509Authorities(), 2)
		assert.True(t, bundle.HasX509Authority(caA))
		assert.True(t, bundle.HasX509Authority(caB))
	})

	t.Run("leaves other trust domains unchanged", func(t *testing.T) {
		bundle, err := merged.GetX509BundleForTrustDomain(otherTD)
		require.NoError(t, err)
		assert.Empty(t, bundle.X509Authorities())
	})
}

func TestMergedBundleSource_VerifiesPeerFromMergedAuthority(t *testing.T) {
	primaryTD := spiffeid.RequireTrustDomainFromString("example.org")
	haTD := spiffeid.RequireTrustDomainFromString("spire-ha")

	rootA, _ := newTestCA(t)
	rootB, rootBKey := newTestCA(t)

	inner := &staticBundleSource{
		bundles: map[spiffeid.TrustDomain]*x509bundle.Bundle{
			primaryTD: x509bundle.FromX509Authorities(primaryTD, []*x509.Certificate{rootA}),
			haTD:      x509bundle.FromX509Authorities(haTD, []*x509.Certificate{rootB}),
		},
	}

	peerID := spiffeid.RequireFromPath(primaryTD, "/oidc-discovery-provider")
	leaf, intermediates := newTestSVIDChain(t, rootB, rootBKey, peerID)

	t.Run("fails without merged bundle", func(t *testing.T) {
		_, _, err := x509svid.Verify(append([]*x509.Certificate{leaf}, intermediates...), inner)
		require.Error(t, err)
	})

	t.Run("succeeds with merged bundle", func(t *testing.T) {
		merged := newMergedBundleSource(inner, primaryTD, []spiffeid.TrustDomain{haTD})
		id, _, err := x509svid.Verify(append([]*x509.Certificate{leaf}, intermediates...), merged)
		require.NoError(t, err)
		assert.Equal(t, peerID, id)
	})
}

func newTestCA(t *testing.T) (*x509.Certificate, crypto.Signer) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, key
}

func newTestSVIDChain(t *testing.T, root *x509.Certificate, rootKey crypto.Signer, id spiffeid.ID) (*x509.Certificate, []*x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{id.URL()},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, key.Public(), rootKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf, nil
}

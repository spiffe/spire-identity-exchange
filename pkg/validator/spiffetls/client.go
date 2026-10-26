// Package spiffetls builds HTTP clients whose TLS is verified against the
// SPIFFE trust bundle, for plugins that fetch OIDC discovery and JWKS documents
// from an endpoint serving an X509-SVID.
//
// Note that SPIFFE TLS does not verify the DNS name. go-spiffe disables Go's
// hostname verification and replaces certificate validation entirely: the peer
// is identified by the SPIFFE ID in its URI SAN and checked by an Authorizer.
// The host in a discovery URL is therefore an address, not an identity.
package spiffetls

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// WorkloadAPIStartupTimeout bounds how long a plugin waits at startup
// for the SPIRE Agent to deliver its first trust bundle.
const WorkloadAPIStartupTimeout = 60 * time.Second

// Authorizer decides whether the SPIFFE ID presented by the discovery endpoint
// is acceptable. Re-exported so callers need not import go-spiffe directly.
type Authorizer = tlsconfig.Authorizer

// AuthorizeID requires the peer to present exactly this SPIFFE ID.
func AuthorizeID(id spiffeid.ID) Authorizer { return tlsconfig.AuthorizeID(id) }

// AuthorizeMemberOf accepts any peer whose SPIFFE ID is in the trust domain.
// Weaker than AuthorizeID: any workload in the domain satisfies it.
func AuthorizeMemberOf(td spiffeid.TrustDomain) Authorizer {
	return tlsconfig.AuthorizeMemberOf(td)
}

// NewBundleSource connects to the Workload API at socketPath and waits for the
// initial trust bundle, giving up after WorkloadAPIStartupTimeout.
func NewBundleSource(socketPath string) (*workloadapi.BundleSource, error) {
	return newBundleSourceWithTimeout(socketPath, WorkloadAPIStartupTimeout)
}

// newBundleSourceWithTimeout is split out so tests can use a short deadline.
func newBundleSourceWithTimeout(socketPath string, timeout time.Duration) (*workloadapi.BundleSource, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("workload API socket path must not be empty")
	}

	// workloadapi.WithAddr requires the unix:// prefix; accept a path with or
	// without it.
	addr := "unix://" + strings.TrimPrefix(socketPath, "unix://")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	source, err := workloadapi.NewBundleSource(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(addr)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to receive the initial trust bundle from the workload API at %s within %s "+
			"(is the SPIRE agent running, and is the socket path correct?): %w", addr, timeout, err)
	}
	return source, nil
}

// NewTrustBundleHTTPClient returns an http.Client that verifies the server
// against the SPIFFE trust bundle fetched from the Workload API at socketPath,
// authorizing the peer with the given Authorizer.
//
// A bundle source is used rather than an X509 source because the client only
// needs to verify the server; it presents no certificate of its own. That also
// avoids requiring this process to hold an SVID.
//
// The returned client owns a Workload API connection that keeps the trust
// bundle current, so it must outlive the calls made through it. There is no way
// to shut it down: the source is intentionally not closed on the success path
// because the caller retains the client for the life of the process. It IS
// closed on every error path here.
func NewTrustBundleHTTPClient(socketPath string, authorizer Authorizer, timeout time.Duration) (*http.Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("workload API socket path must not be empty")
	}
	if authorizer == nil {
		return nil, fmt.Errorf("authorizer must not be nil")
	}

	source, err := NewBundleSource(socketPath)
	if err != nil {
		return nil, err
	}

	return newClientWithBundleSource(source, authorizer, timeout), nil
}

// newClientWithBundleSource is split out so tests can supply a bundle source
// without a Workload API socket.
func newClientWithBundleSource(bundle x509bundle.Source, authorizer Authorizer, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.TLSClientConfig(bundle, authorizer),
		},
	}
}

// Package delegated wraps the SPIRE Agent Delegated Identity API in a small
// one-shot client tailored to the spire-identity-exchange REST flow.
//
// The Delegated Identity API is a streaming RPC; this wrapper takes the first
// message off SubscribeToX509SVIDs and closes the stream, which matches the
// "validate token → fetch SVID → return" shape of the REST handler. Keeping
// long-lived subscriptions open per request would not buy anything: the
// exchange terminates the request as soon as it has a cert to return.
//
// The transport is gRPC over a Unix domain socket; security is provided by
// the kernel (SO_PEERCRED) plus the agent's authorized_delegates check on
// the caller's SPIFFE ID. No client cert is presented — the listener's
// filesystem permissions are the only network-level defense.
package delegated

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ErrNoMatchingEntry indicates the agent had no entry whose selectors are a
// subset of those requested. Translated to HTTP 404 by callers.
var ErrNoMatchingEntry = errors.New("no registration entry matches the requested selectors")

// ErrPermissionDenied indicates the caller's SPIFFE ID is not in the agent's
// authorized_delegates configuration. Translated to HTTP 503 by callers — it
// is an operator misconfiguration, not a request-level error.
var ErrPermissionDenied = errors.New("caller not in authorized_delegates")

// ErrUnavailable indicates the agent's delegated socket is not reachable.
// Translated to HTTP 503 by callers.
var ErrUnavailable = errors.New("delegated identity API unavailable")

// X509SVID is the wire-decoded result of an X.509 SVID fetch.
type X509SVID struct {
	SpiffeID   string
	CertChain  [][]byte // ASN.1 DER, leaf first
	PrivateKey []byte   // PKCS#8 DER
	ExpiresAt  time.Time
	Hint       string
}

// JWTSVID is the wire-decoded result of a JWT SVID fetch.
type JWTSVID struct {
	SpiffeID  string
	Token     string
	ExpiresAt time.Time
	Hint      string
}

// Client is a long-lived handle to the SPIRE Agent's Delegated Identity API.
// One Client per process is sufficient; gRPC manages the underlying connection
// (reconnects, keepalives).
type Client struct {
	conn *grpc.ClientConn
	api  delegatedidentityv1.DelegatedIdentityClient
}

// New opens a connection to the agent's delegated socket. The socket path must
// be an absolute filesystem path; it is opened as `unix://<path>`.
//
// The connection is lazy — `New` does not block on the socket being reachable.
// The first RPC will surface ErrUnavailable if the agent is not running.
func New(socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, errors.New("delegated socket path is required")
	}
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial delegated socket %s: %w", socketPath, err)
	}
	return &Client{
		conn: conn,
		api:  delegatedidentityv1.NewDelegatedIdentityClient(conn),
	}, nil
}

// Close releases the underlying gRPC connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// FetchX509SVID asks the agent for an X.509-SVID whose entry selectors are a
// subset of those provided. The call uses the streaming SubscribeToX509SVIDs
// RPC under the hood, takes the first message, and closes the stream.
//
// Returns ErrNoMatchingEntry if the agent's cache has no matching entry —
// either the entries haven't propagated yet, the selectors don't match, or
// the entries are parented elsewhere and SIX never received them.
func (c *Client) FetchX509SVID(ctx context.Context, selectors []*types.Selector) (*X509SVID, error) {
	if len(selectors) == 0 {
		return nil, errors.New("at least one selector is required")
	}

	// A short cancel context guards against the stream hanging if the agent
	// accepts the connection but never sends a message. The first message is
	// the agent's snapshot of matching SVIDs, which it should produce
	// immediately after attesting the caller.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := c.api.SubscribeToX509SVIDs(streamCtx, &delegatedidentityv1.SubscribeToX509SVIDsRequest{
		Selectors: selectors,
	})
	if err != nil {
		return nil, translateRPCError(err)
	}

	resp, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrNoMatchingEntry
		}
		return nil, translateRPCError(err)
	}

	if len(resp.X509Svids) == 0 {
		return nil, ErrNoMatchingEntry
	}

	first := resp.X509Svids[0]
	if first == nil || first.X509Svid == nil {
		return nil, fmt.Errorf("delegated identity API returned nil SVID")
	}

	return &X509SVID{
		SpiffeID:   spiffeIDString(first.X509Svid.Id),
		CertChain:  first.X509Svid.CertChain,
		PrivateKey: first.X509SvidKey,
		ExpiresAt:  time.Unix(first.X509Svid.ExpiresAt, 0),
		Hint:       first.X509Svid.Hint,
	}, nil
}

// FetchJWTSVID asks the agent for a JWT-SVID matching the selectors and
// audiences. This is a unary RPC; no stream handling required.
func (c *Client) FetchJWTSVID(ctx context.Context, selectors []*types.Selector, audiences []string) (*JWTSVID, error) {
	if len(selectors) == 0 {
		return nil, errors.New("at least one selector is required")
	}
	if len(audiences) == 0 {
		return nil, errors.New("at least one audience is required")
	}

	resp, err := c.api.FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{
		Audience:  audiences,
		Selectors: selectors,
	})
	if err != nil {
		return nil, translateRPCError(err)
	}

	if len(resp.Svids) == 0 {
		return nil, ErrNoMatchingEntry
	}

	first := resp.Svids[0]
	if first == nil {
		return nil, fmt.Errorf("delegated identity API returned nil JWT-SVID")
	}

	return &JWTSVID{
		SpiffeID:  spiffeIDString(first.Id),
		Token:     first.Token,
		ExpiresAt: time.Unix(first.ExpiresAt, 0),
		Hint:      first.Hint,
	}, nil
}

func spiffeIDString(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return "spiffe://" + id.TrustDomain + id.Path
}

// translateRPCError maps gRPC status codes onto the package-level sentinel
// errors so HTTP handlers can pick the right status code without parsing the
// gRPC error string.
func translateRPCError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.PermissionDenied:
		return fmt.Errorf("%w: %s", ErrPermissionDenied, st.Message())
	case codes.NotFound, codes.InvalidArgument:
		return fmt.Errorf("%w: %s", ErrNoMatchingEntry, st.Message())
	case codes.Unavailable, codes.DeadlineExceeded:
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	default:
		return err
	}
}

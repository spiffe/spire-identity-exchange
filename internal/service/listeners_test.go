package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
)

const testSPIFFEID = "spiffe://example.org/service/test"

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

func testECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// testSelfSignedCertFiles writes a self-signed cert/key pair carrying
// DNS:localhost, for use as server.tls.certFile/keyFile.
func testSelfSignedCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key := testECDSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

// testSVID mints a CA and a leaf carrying only a URI SAN, the way a real
// X509-SVID looks — no DNS SAN, so ordinary hostname verification does not apply
// to it.
func testSVID(t *testing.T, spiffeID string) (leafDER, keyPKCS8 []byte, ca *x509.Certificate) {
	t.Helper()

	caKey := testECDSAKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)

	id, err := url.Parse(spiffeID)
	require.NoError(t, err)

	leafKey := testECDSAKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// go-spiffe rejects a leaf that is a CA or can sign certs.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{id},
	}
	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	keyPKCS8, err = x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)

	return leafDER, keyPKCS8, ca
}

// ---------------------------------------------------------------------------
// Fake SPIFFE Workload API
// ---------------------------------------------------------------------------

// fakeWorkloadAPI serves one X509-SVID response and then holds the stream open.
// A nil response makes it silent, which is what drives the SVID-unavailable path.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	resp *workload.X509SVIDResponse
}

func (f *fakeWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if f.resp != nil {
		if err := stream.Send(f.resp); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// startFakeWorkloadAPI returns the unix socket path the fake is listening on.
// The socket lives under a short /tmp directory rather than t.TempDir(): macOS
// caps sun_path at 104 bytes and a t.TempDir() path plus the test name can
// exceed it.
func startFakeWorkloadAPI(t *testing.T, resp *workload.X509SVIDResponse) string {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "sie-wl")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "wl.sock")
	ln, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, &fakeWorkloadAPI{resp: resp})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	return sock
}

func testSVIDResponse(t *testing.T, spiffeID string) (*workload.X509SVIDResponse, *x509.Certificate) {
	t.Helper()
	leafDER, keyPKCS8, ca := testSVID(t, spiffeID)
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    spiffeID,
			X509Svid:    leafDER,
			X509SvidKey: keyPKCS8,
			Bundle:      ca.Raw,
		}},
	}, ca
}

// ---------------------------------------------------------------------------
// listenerPlans
// ---------------------------------------------------------------------------

func TestListenerPlans(t *testing.T) {
	fileTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	spiffeTLS := &tls.Config{MinVersion: tls.VersionTLS13}

	type want struct {
		name string
		kind serverKind
		port int
		tls  *tls.Config
	}

	cases := []struct {
		name   string
		server config.ServerConfig
		want   []want
	}{
		{
			name:   "nothing enabled",
			server: config.ServerConfig{},
		},
		{
			name: "file only",
			server: config.ServerConfig{TLS: config.TLSConfig{
				GRPC: config.ListenerConfig{Enable: true, Port: 8443},
				REST: config.ListenerConfig{Enable: true, Port: 8444},
			}},
			want: []want{
				{"tls.grpc", kindGRPC, 8443, fileTLS},
				{"tls.rest", kindREST, 8444, fileTLS},
			},
		},
		{
			name: "spiffe only",
			server: config.ServerConfig{SPIFFE: config.SPIFFEServerConfig{
				GRPC: config.ListenerConfig{Enable: true, Port: 8543},
				REST: config.ListenerConfig{Enable: true, Port: 8544},
			}},
			want: []want{
				{"spiffe.grpc", kindGRPC, 8543, spiffeTLS},
				{"spiffe.rest", kindREST, 8544, spiffeTLS},
			},
		},
		{
			name: "all four",
			server: config.ServerConfig{
				TLS: config.TLSConfig{
					GRPC: config.ListenerConfig{Enable: true, Port: 8443},
					REST: config.ListenerConfig{Enable: true, Port: 8444},
				},
				SPIFFE: config.SPIFFEServerConfig{
					GRPC: config.ListenerConfig{Enable: true, Port: 8543},
					REST: config.ListenerConfig{Enable: true, Port: 8544},
				},
			},
			want: []want{
				{"tls.grpc", kindGRPC, 8443, fileTLS},
				{"tls.rest", kindREST, 8444, fileTLS},
				{"spiffe.grpc", kindGRPC, 8543, spiffeTLS},
				{"spiffe.rest", kindREST, 8544, spiffeTLS},
			},
		},
		{
			// The zero-port rule: enable alone is not enough. This is the case a
			// parallel enabled/candidates pair would silently get wrong.
			name: "zero port disables despite enable",
			server: config.ServerConfig{
				TLS: config.TLSConfig{
					GRPC: config.ListenerConfig{Enable: true, Port: 0},
					REST: config.ListenerConfig{Enable: true, Port: 8444},
				},
				SPIFFE: config.SPIFFEServerConfig{
					GRPC: config.ListenerConfig{Enable: true, Port: 8543},
					REST: config.ListenerConfig{Enable: true, Port: 0},
				},
			},
			want: []want{
				{"tls.rest", kindREST, 8444, fileTLS},
				{"spiffe.grpc", kindGRPC, 8543, spiffeTLS},
			},
		},
		{
			name: "port set but not enabled",
			server: config.ServerConfig{
				TLS:    config.TLSConfig{GRPC: config.ListenerConfig{Enable: false, Port: 8443}},
				SPIFFE: config.SPIFFEServerConfig{REST: config.ListenerConfig{Enable: true, Port: 8544}},
			},
			want: []want{
				{"spiffe.rest", kindREST, 8544, spiffeTLS},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plans := listenerPlans(&config.SpireIdentityExchangeConfig{Server: c.server}, fileTLS, spiffeTLS)
			require.Len(t, plans, len(c.want))
			for i, w := range c.want {
				assert.Equal(t, w.name, plans[i].name)
				assert.Equal(t, w.kind, plans[i].kind, "kind for %s", w.name)
				assert.Equal(t, w.port, plans[i].port, "port for %s", w.name)
				assert.Same(t, w.tls, plans[i].tls, "tls config for %s", w.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Four-listener startup and shutdown
// ---------------------------------------------------------------------------

// testFreePorts reserves n ports and releases them. There is an inherent race
// with anything else on the host claiming one in between, which the caller
// handles by retrying.
func testFreePorts(t *testing.T, n int) []int {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", ":0")
		require.NoError(t, err)
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		require.NoError(t, ln.Close())
	}
	return ports
}

// testDialLeaf completes a TLS handshake and returns the leaf the server
// presented.
func testDialLeaf(t *testing.T, port int, cfg *tls.Config) (*x509.Certificate, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), cfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	certs := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, certs)
	return certs[0], nil
}

func testWaitForPort(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		// Readiness probe only — identity is asserted separately below.
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // readiness probe
			MinVersion:         tls.VersionTLS13,
		})
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %d never accepted a TLS handshake: %v", port, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRunBindsAllFourListeners covers the whole startup path: both certificate
// sources resolved, four listeners bound before any of them serves, each serving
// the certificate for its own source, and a clean shutdown that releases every
// port.
func TestRunBindsAllFourListeners(t *testing.T) {
	certPath, keyPath := testSelfSignedCertFiles(t)
	resp, ca := testSVIDResponse(t, testSPIFFEID)
	sock := startFakeWorkloadAPI(t, resp)

	// Retry on a lost port race rather than failing the suite for it.
	var runErr error
	for attempt := 1; ; attempt++ {
		ports := testFreePorts(t, 4)
		runErr = runFourListeners(t, cfg4(certPath, keyPath, sock, ports), ports, ca)
		if runErr == nil || !strings.Contains(runErr.Error(), "failed to bind") || attempt == 3 {
			break
		}
		t.Logf("attempt %d lost a port race, retrying: %v", attempt, runErr)
	}
	require.NoError(t, runErr)
}

func cfg4(certPath, keyPath, sock string, ports []int) *config.SpireIdentityExchangeConfig {
	return &config.SpireIdentityExchangeConfig{
		SPIRE: config.SPIREConfig{
			TrustDomain:             "example.org",
			AgentWorkloadSocketPath: sock,
			// The REST listeners need a delegated client. grpc.NewClient dials
			// lazily, so an absent socket still lets the listener bind — this test
			// asserts listener wiring, not request handling.
			AgentDelegatedSocketPath: "/tmp/sie-test-absent-delegated.sock",
		},
		Server: config.ServerConfig{
			MetricsPort: 0, // Run does not start the metrics server.
			TLS: config.TLSConfig{
				CertFile: certPath,
				KeyFile:  keyPath,
				GRPC:     config.ListenerConfig{Enable: true, Port: ports[0]},
				REST:     config.ListenerConfig{Enable: true, Port: ports[1]},
			},
			SPIFFE: config.SPIFFEServerConfig{
				GRPC: config.ListenerConfig{Enable: true, Port: ports[2]},
				REST: config.ListenerConfig{Enable: true, Port: ports[3]},
			},
		},
	}
}

func runFourListeners(t *testing.T, cfg *config.SpireIdentityExchangeConfig, ports []int, ca *x509.Certificate) error {
	t.Helper()
	logger := zaptest.NewLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runSpireIdentityExchangeServer(ctx, cfg, nil, nil, nil, nil, logger)
	}()

	// Surface a startup failure (including a lost port race) instead of blocking
	// in testWaitForPort until its deadline.
	select {
	case err := <-done:
		if err == nil {
			return fmt.Errorf("server returned before the test cancelled it")
		}
		return err
	case <-time.After(200 * time.Millisecond):
	}

	for _, p := range ports {
		testWaitForPort(t, p)
	}

	// The file-sourced listeners present the self-signed cert, which carries
	// DNS:localhost, so ordinary verification applies.
	fileRoots := x509.NewCertPool()
	pemBytes, err := os.ReadFile(cfg.Server.TLS.CertFile)
	require.NoError(t, err)
	require.True(t, fileRoots.AppendCertsFromPEM(pemBytes))

	for _, p := range ports[:2] {
		leaf, err := testDialLeaf(t, p, &tls.Config{
			ServerName: "localhost",
			RootCAs:    fileRoots,
			MinVersion: tls.VersionTLS13,
		})
		require.NoError(t, err, "file-sourced listener on %d", p)
		assert.Equal(t, "localhost", leaf.Subject.CommonName, "port %d should serve the file certificate", p)
		assert.Empty(t, leaf.URIs, "the file certificate should carry no SPIFFE URI SAN")
	}

	// The SPIFFE listeners present an X509-SVID. It has a URI SAN and no DNS SAN,
	// so hostname verification cannot apply; verify the chain against the test CA
	// explicitly and assert the identity from the SAN.
	svidRoots := x509.NewCertPool()
	svidRoots.AddCert(ca)

	for _, p := range ports[2:] {
		leaf, err := testDialLeaf(t, p, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // SVIDs have no DNS SAN; verified explicitly below
			MinVersion:         tls.VersionTLS13,
		})
		require.NoError(t, err, "SPIFFE listener on %d", p)

		require.Len(t, leaf.URIs, 1, "port %d should serve an SVID with one URI SAN", p)
		assert.Equal(t, testSPIFFEID, leaf.URIs[0].String())

		_, err = leaf.Verify(x509.VerifyOptions{Roots: svidRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		assert.NoError(t, err, "SVID on port %d should chain to the workload API bundle", p)
	}

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "cancelling the context should be a clean shutdown")
	case <-time.After(20 * time.Second):
		t.Fatal("server did not shut down after context cancellation")
	}

	// Every listener must be released, or a supervisor restart would re-fail.
	for _, p := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		require.NoError(t, err, "port %d was still bound after shutdown", p)
		require.NoError(t, ln.Close())
	}

	return nil
}

// ---------------------------------------------------------------------------
// SPIFFE TLS config
// ---------------------------------------------------------------------------

func TestNewSPIFFETLSConfig(t *testing.T) {
	resp, _ := testSVIDResponse(t, testSPIFFEID)
	sock := startFakeWorkloadAPI(t, resp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+sock))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	cfg, closer, err := newSPIFFETLSConfig(ctx, client, 10*time.Second, zaptest.NewLogger(t))
	require.NoError(t, err)
	defer func() { _ = closer.Close() }()

	require.NotNil(t, cfg.GetCertificate)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	// Server-side TLS only: no client certificate is requested.
	assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
	assert.Nil(t, cfg.VerifyPeerCertificate)

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
}

// TestNewSPIFFETLSConfigTimeout pins the operator-facing failure when the agent
// never hands out an SVID — a missing registration entry is the likely cause, so
// the message has to say so.
func TestNewSPIFFETLSConfigTimeout(t *testing.T) {
	sock := startFakeWorkloadAPI(t, nil) // silent: never sends a response

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+sock))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	start := time.Now()
	cfg, closer, err := newSPIFFETLSConfig(ctx, client, 200*time.Millisecond, zaptest.NewLogger(t))
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, cfg)
	assert.Nil(t, closer)
	assert.Contains(t, err.Error(), "workload API")
	assert.Contains(t, err.Error(), "registered")
	assert.Less(t, elapsed, 5*time.Second, "should fail on the supplied timeout, not the production one")
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

// TestShutdownAllForcesAfterTimeout covers the escalation path: a graceful stop
// that only completes once force() runs must still be waited for, so the caller
// never returns with teardown goroutines in flight.
func TestShutdownAllForcesAfterTimeout(t *testing.T) {
	forced := make(chan struct{})
	gracefulReturned := make(chan struct{})

	entry := &serverEntry{
		name: "test.grpc",
		port: 1,
		graceful: func(context.Context) {
			<-forced
			// Unwinding takes a moment. Without this the assertion below could
			// pass by luck against a shutdownAll that returns straight after
			// forcing; with it, only actually waiting satisfies the test.
			time.Sleep(100 * time.Millisecond)
			close(gracefulReturned)
		},
		force: func() { close(forced) },
	}

	done := make(chan struct{})
	go func() {
		shutdownAll([]*serverEntry{entry}, 50*time.Millisecond, zaptest.NewLogger(t))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdownAll did not return")
	}

	// Both must already be closed by the time shutdownAll returned.
	select {
	case <-forced:
	default:
		t.Error("force() was never called after the graceful timeout")
	}
	select {
	case <-gracefulReturned:
	default:
		t.Error("shutdownAll returned before the graceful goroutine finished")
	}
}

func TestShutdownAllGracefulPath(t *testing.T) {
	var forceCalled bool
	entry := &serverEntry{
		name:     "test.rest",
		port:     2,
		graceful: func(context.Context) {},
		force:    func() { forceCalled = true },
	}

	shutdownAll([]*serverEntry{entry}, 5*time.Second, zaptest.NewLogger(t))
	assert.False(t, forceCalled, "a graceful stop within the timeout must not escalate")
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

func TestRunNoListenerEnabled(t *testing.T) {
	cfg := &config.SpireIdentityExchangeConfig{
		Server: config.ServerConfig{MetricsPort: 4950},
		SPIRE:  config.SPIREConfig{TrustDomain: "example.org"},
	}

	err := runSpireIdentityExchangeServer(context.Background(), cfg, nil, nil, nil, nil, zaptest.NewLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no listener enabled")
}

func TestRunNilConfig(t *testing.T) {
	err := runSpireIdentityExchangeServer(context.Background(), nil, nil, nil, nil, nil, zaptest.NewLogger(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is nil")
}

package service

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	shutdownTimeout    = 5 * time.Second
	serverStartTimeout = 60 * time.Second
	// How long to wait for teardown to finish after escalating to a forced stop.
	// grpc.Server.Stop and http.Server.Close both close their listeners
	// synchronously, so this is only a backstop against a connection that refuses
	// to unwind.
	forceStopGrace = 2 * time.Second

	// HTTP gateway timeouts. The gateway is internet-facing; defaults are aimed at
	// short MintCertificate REST calls — slow-client traffic should not be able to
	// hold the listener open indefinitely.
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 30 * time.Second
	httpWriteTimeout      = 30 * time.Second
	httpIdleTimeout       = 60 * time.Second
	// MintCertificate requests carry a JWT (a few KB) and an optional CSR (~1 KB DER
	// base64-encoded). 256 KiB is well above legitimate sizes and small enough that
	// a malicious client cannot trickle a giant body to exhaust memory.
	httpMaxRequestBodyBytes int64 = 256 * 1024
)

// trustBundleCache implements the workloadapi.X509ContextWatcher interface.
type trustBundleCache struct {
	mu       sync.RWMutex
	pemBytes []byte
	logger   *zap.Logger
}

func (c *trustBundleCache) Get() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.pemBytes...)
}

// OnX509ContextUpdate matches the real workloadapi.X509ContextWatcher interface signature.
func (c *trustBundleCache) OnX509ContextUpdate(x509Ctx *workloadapi.X509Context) {
	if x509Ctx == nil || x509Ctx.Bundles == nil {
		return
	}

	var localPemBytes []byte
	for _, bundle := range x509Ctx.Bundles.Bundles() {
		for _, cert := range bundle.X509Authorities() {
			b := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			localPemBytes = append(localPemBytes, b...)
		}
	}

	c.mu.Lock()
	c.pemBytes = localPemBytes
	c.mu.Unlock()
}

// OnX509ContextWatchError matches the real workloadapi.X509ContextWatcher interface signature.
// go-spiffe handles reconnect internally so these are transient.
func (c *trustBundleCache) OnX509ContextWatchError(err error) {
	if c.logger != nil {
		c.logger.Info("workload API watcher transient error", zap.Error(err))
	}
}

type CertReloader struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func (cr *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cert, nil
}

func (cr *CertReloader) Reload() error {
	newCert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return err
	}
	cr.mu.Lock()
	cr.cert = &newCert
	cr.mu.Unlock()
	return nil
}

// serverKind distinguishes the two protocol surfaces a listener can serve.
type serverKind int

const (
	kindGRPC serverKind = iota
	kindREST
)

// listenerPlan is a listener we intend to open, resolved from configuration
// before anything is bound.
type listenerPlan struct {
	name string // "tls.grpc" | "tls.rest" | "spiffe.grpc" | "spiffe.rest"
	kind serverKind
	port int
	tls  *tls.Config
}

// serverEntry is one bound listener plus its lifecycle hooks. Binding is
// separated from serving so a failure to bind the fourth listener tears down the
// first three without any of them having accepted a connection.
type serverEntry struct {
	name     string
	port     int
	ln       net.Listener
	serve    func() error          // blocks until stopped
	graceful func(context.Context) // GracefulStop / Shutdown
	force    func()                // Stop / Close; must be idempotent
}

// newFileTLSConfig builds the TLS config for the listeners served with an on-disk
// certificate, and starts the background reloader that picks up rotations.
func newFileTLSConfig(ctx context.Context, tc config.TLSConfig, logger *zap.Logger) (*tls.Config, error) {
	reloader := &CertReloader{
		certPath: tc.CertFile,
		keyPath:  tc.KeyFile,
	}
	if err := reloader.Reload(); err != nil {
		return nil, fmt.Errorf("failed to load initial TLS certificate: %w", err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := reloader.Reload(); err != nil {
					logger.Error("failed to reload TLS certificate",
						zap.String("cert_file", reloader.certPath),
						zap.String("key_file", reloader.keyPath),
						zap.Error(err),
					)
				} else {
					logger.Debug("TLS certificate reloaded")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	logger.Info("file-sourced TLS certificate loaded",
		zap.String("cert_file", tc.CertFile),
		zap.String("key_file", tc.KeyFile))

	return &tls.Config{
		GetCertificate: reloader.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}, nil
}

// newSPIFFETLSConfig builds the TLS config for the listeners served with this
// process's own X509-SVID, and returns the source as a Closer the caller must
// close. Client authentication is unchanged from the file-sourced listeners:
// neither ClientAuth nor VerifyPeerCertificate is set, so no client certificate
// is requested.
//
// timeout bounds the initial SVID fetch. NewX509Source blocks until the agent
// hands one out, so without a bound a not-yet-ready agent — or a missing
// registration entry for this process — hangs startup indefinitely.
func newSPIFFETLSConfig(ctx context.Context, client *workloadapi.Client, timeout time.Duration, logger *zap.Logger) (*tls.Config, io.Closer, error) {
	bootCtx, bootCancel := context.WithTimeout(ctx, timeout)
	defer bootCancel()

	source, err := workloadapi.NewX509Source(bootCtx, workloadapi.WithClient(client))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to obtain the server SVID from the workload API within %s "+
			"(is the SPIRE agent running, and is this exchange's SPIFFE ID registered?): %w", timeout, err)
	}

	svid, err := source.GetX509SVID()
	if err != nil {
		_ = source.Close()
		return nil, nil, fmt.Errorf("failed to read the server SVID: %w", err)
	}
	logger.Info("serving SPIFFE listeners with this process's own X509-SVID",
		zap.String("spiffe_id", svid.ID.String()))

	// go-spiffe runs the source's watch goroutine under context.Background(), so
	// cancelling ctx does not stop it — only Close() does. Closing the source does
	// not close a client supplied via WithClient, so the caller still owns that.
	return &tls.Config{
		GetCertificate: tlsconfig.GetCertificate(source),
		MinVersion:     tls.VersionTLS13,
	}, source, nil
}

// listenerPlans resolves the enabled listeners, in a stable order, pairing each
// with the TLS config for its certificate source.
func listenerPlans(cfg *config.SpireIdentityExchangeConfig, fileTLS, spiffeTLS *tls.Config) []listenerPlan {
	// Each candidate carries the ListenerConfig it came from, so the port and the
	// enable flag are read from one value and cannot drift apart.
	candidates := []struct {
		name     string
		kind     serverKind
		listener config.ListenerConfig
		tls      *tls.Config
	}{
		{"tls.grpc", kindGRPC, cfg.Server.TLS.GRPC, fileTLS},
		{"tls.rest", kindREST, cfg.Server.TLS.REST, fileTLS},
		{"spiffe.grpc", kindGRPC, cfg.Server.SPIFFE.GRPC, spiffeTLS},
		{"spiffe.rest", kindREST, cfg.Server.SPIFFE.REST, spiffeTLS},
	}

	plans := make([]listenerPlan, 0, len(candidates))
	for _, c := range candidates {
		if !c.listener.Enabled() {
			continue
		}
		plans = append(plans, listenerPlan{
			name: c.name,
			kind: c.kind,
			port: c.listener.Port,
			tls:  c.tls,
		})
	}
	return plans
}

// newServerEntry wires a bound listener to a protocol implementation. Both the
// gRPC handler and the REST handler are shared across entries — only the TLS
// config differs between the two certificate sources.
func newServerEntry(p listenerPlan, ln net.Listener, grpcHandler proto.SpireIdentityExchangeApiServer, restHandler http.Handler) *serverEntry {
	e := &serverEntry{name: p.name, port: p.port, ln: ln}

	switch p.kind {
	case kindGRPC:
		// Credentials are bound to the server, not the listener, so each
		// certificate source needs its own grpc.Server even though one server
		// can serve several listeners.
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(p.tls)))
		proto.RegisterSpireIdentityExchangeApiServer(srv, grpcHandler)
		reflection.Register(srv)
		e.serve = func() error { return srv.Serve(ln) }
		// GracefulStop takes no context and can block on a long-lived stream;
		// the caller's shutdown timeout plus force() is what bounds it.
		e.graceful = func(context.Context) { srv.GracefulStop() }
		e.force = srv.Stop

	case kindREST:
		srv := &http.Server{
			Handler: restHandler,
			// http.Server mutates TLSConfig (NextProtos), so the two REST
			// listeners must not share one *tls.Config.
			TLSConfig:         p.tls.Clone(),
			ReadHeaderTimeout: httpReadHeaderTimeout,
			ReadTimeout:       httpReadTimeout,
			WriteTimeout:      httpWriteTimeout,
			IdleTimeout:       httpIdleTimeout,
		}
		e.serve = func() error { return srv.ServeTLS(ln, "", "") }
		e.graceful = func(shutdownCtx context.Context) { _ = srv.Shutdown(shutdownCtx) }
		// Shutdown does not wait on hijacked connections; Close is the escalation.
		e.force = func() { _ = srv.Close() }
	}

	return e
}

// shutdownAll gracefully stops every entry in parallel, escalating to a forced
// stop if the timeout expires.
func shutdownAll(entries []*serverEntry, timeout time.Duration, logger *zap.Logger) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	stopped := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for _, e := range entries {
			wg.Add(1)
			go func(e *serverEntry) {
				defer wg.Done()
				e.graceful(shutdownCtx)
			}(e)
		}
		wg.Wait()
		close(stopped)
	}()

	select {
	case <-stopped:
		logger.Info("Server shutdown completed")
	case <-shutdownCtx.Done():
		logger.Warn("Shutdown timeout exceeded, forcing stop")
		for _, e := range entries {
			e.force()
		}
		// force() is what unblocks the graceful calls, so this returns promptly.
		// Waiting means the caller does not return while the graceful and serve
		// goroutines are still unwinding; the bound only keeps a pathological
		// hijacked connection from hanging shutdown forever.
		select {
		case <-stopped:
			logger.Info("Server shutdown completed after forced stop")
		case <-time.After(forceStopGrace):
			logger.Warn("Forced stop did not complete in time; abandoning teardown")
		}
	}
}

func entryNames(entries []*serverEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, fmt.Sprintf("%s:%d", e.name, e.port))
	}
	return names
}

// Run runs spire-identity-exchange gRPC server (and optionally HTTP REST server) and waits for
// termination signals. Pass nil for a validator to disable that auth method.
// Returns the first error encountered during startup or runtime so the caller can exit
// non-zero — a swallowed bind/TLS failure looks identical to a clean shutdown to a
// supervisor and would mask broken deployments.
func Run(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient SpireClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	if err := runSpireIdentityExchangeServer(ctx, cfg, spireClient, githubOIDCValidator, k8sSATokenValidator, metrics, logger); err != nil {
		logger.Error("spire-identity-exchange error", zap.Error(err))
		return err
	}
	logger.Info("spire-identity-exchange server stopped gracefully")
	return nil
}

// runSpireIdentityExchangeServer starts the gRPC server and/or the HTTP/REST gateway
// based on configuration. Setting either port to 0 disables that respective protocol.
func runSpireIdentityExchangeServer(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient SpireClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	// Config validation catches this too, but callers can build a config directly
	// and reach this function without going through Validate().
	if !cfg.Server.AnyEnabled() {
		return fmt.Errorf("no listener enabled; nothing to run")
	}

	// A listener with enable: true and port 0 is disabled by design, not an error.
	// Say so, or the missing port looks like a bug.
	for _, l := range cfg.Server.NamedListeners() {
		if l.Config.Enable && l.Config.Port == 0 {
			logger.Warn("listener enabled but port is 0; treating as disabled", zap.String("listener", l.Name))
		}
	}

	// Start key syncers for any validator that supports it
	for _, v := range []validator.TokenValidator{githubOIDCValidator, k8sSATokenValidator} {
		if v == nil {
			continue
		}
		if syncer, ok := v.(validator.KeySynchronizer); ok {
			logger.Info("Starting key synchronizer", zap.String("validator", fmt.Sprintf("%T", v)))
			if err := syncer.Start(ctx); err != nil {
				return fmt.Errorf("failed to start key synchronizer for %T: %w", v, err)
			}
		}
	}

	// Shared delegated client for both surfaces. Needed by REST always; by
	// gRPC only on the PluginAuth path (port open + plugins registered).
	var (
		delegatedClient *delegated.Client
		err             error
	)
	needDelegated := cfg.Server.AnyRESTEnabled() ||
		(cfg.Server.AnyGRPCEnabled() && len(cfg.Auth.LoadedPlugins) > 0)
	if needDelegated {
		logger.Info("connecting to delegated identity socket", zap.String("socket_path", cfg.SPIRE.AgentDelegatedSocketPath))
		delegatedClient, err = delegated.New(cfg.SPIRE.AgentDelegatedSocketPath)
		if err != nil {
			return fmt.Errorf("failed to create delegated identity client: %w", err)
		}
		defer func() {
			_ = delegatedClient.Close()
		}()
	}

	handler, err := NewGRPCHandler(spireClient, delegatedClient, cfg, githubOIDCValidator, k8sSATokenValidator, metrics, logger)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server handler: %w", err)
	}

	// --- Workload API client ---
	// Shared by the REST trust-bundle watcher and the SPIFFE listeners' X509
	// source: one UDS connection, one dial/backoff policy, two independent
	// FetchX509SVID streams.
	var wlaClient *workloadapi.Client
	if cfg.Server.AnyRESTEnabled() || cfg.Server.SPIFFEEnabled() {
		socketAddr := "unix://" + cfg.SPIRE.AgentWorkloadSocketPath
		logger.Info("connecting to workload API", zap.String("socket_path", socketAddr))

		wlaClient, err = workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
		if err != nil {
			return fmt.Errorf("failed to create workload API client: %w", err)
		}
		defer func() {
			_ = wlaClient.Close()
		}()
	}

	// --- Trust bundle cache (REST only) ---
	// Fed by WatchX509Context rather than derived from the X509Source below: this
	// concatenates the authorities of every trust domain in the context, which
	// federated callers depend on, and X509Source only exposes a per-trust-domain
	// bundle accessor.
	var cache *trustBundleCache
	if cfg.Server.AnyRESTEnabled() {
		cache = &trustBundleCache{logger: logger}
		go func() {
			if watchErr := wlaClient.WatchX509Context(ctx, cache); watchErr != nil {
				logger.Error("workload API watcher stopped with error", zap.Error(watchErr))
			}
		}()
	}

	// --- TLS configs, one per certificate source ---
	var fileTLS, spiffeTLS *tls.Config
	if cfg.Server.FileTLSEnabled() {
		fileTLS, err = newFileTLSConfig(childCtx, cfg.Server.TLS, logger)
		if err != nil {
			return err
		}
	}
	if cfg.Server.SPIFFEEnabled() {
		var source io.Closer
		spiffeTLS, source, err = newSPIFFETLSConfig(ctx, wlaClient, serverStartTimeout, logger)
		if err != nil {
			return err
		}
		defer func() {
			_ = source.Close()
		}()
	}

	// --- REST handler, built once and shared by both REST listeners ---
	// The handlers are stateless closures and ServeMux is safe for concurrent use.
	var restHandler http.Handler
	if cfg.Server.AnyRESTEnabled() {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/trustbundle/x509", handleTrustBundleX509(cache, logger))
		purposeResolver := validator.NewPurposeResolver(validator.PurposeMode(cfg.PurposeMode))
		mux.HandleFunc("POST /api/v1/svid/{stack}/x509", handleGetX509SVID(cfg, cache, delegatedClient, purposeResolver, logger))
		mux.HandleFunc("POST /api/v1/svid/{stack}/jwt", handleGetJWTSVID(cfg, delegatedClient, purposeResolver, logger))
		restHandler = http.MaxBytesHandler(mux, httpMaxRequestBodyBytes)
	}

	// --- Bind every listener before serving any of them ---
	// A failure partway through then leaves nothing bound and nothing accepting,
	// which is what a supervisor expects from a failed start.
	plans := listenerPlans(cfg, fileTLS, spiffeTLS)
	entries := make([]*serverEntry, 0, len(plans))
	allBound := false
	defer func() {
		if !allBound {
			for _, e := range entries {
				_ = e.ln.Close()
			}
		}
	}()
	for _, p := range plans {
		ln, listenErr := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
		if listenErr != nil {
			return fmt.Errorf("failed to bind %s on port %d: %w", p.name, p.port, listenErr)
		}
		entries = append(entries, newServerEntry(p, ln, handler, restHandler))
		logger.Info("listener bound", zap.String("listener", p.name), zap.Int("port", p.port))
	}
	allBound = true

	errCh := make(chan error, len(entries))
	for _, e := range entries {
		go func(e *serverEntry) {
			serveErr := e.serve()
			// A graceful stop returns nil (gRPC) or ErrServerClosed (HTTP).
			// Forwarding those would race the runtime-error select below and turn
			// a clean shutdown into a non-zero exit.
			if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, grpc.ErrServerStopped) {
				return
			}
			errCh <- fmt.Errorf("%s: %w", e.name, serveErr)
		}(e)
	}

	// Give the listeners a moment to start; surface any immediate serve errors.
	select {
	case serveErr := <-errCh:
		shutdownAll(entries, shutdownTimeout, logger)
		return fmt.Errorf("failed to start server: %w", serveErr)
	case <-ctx.Done():
		logger.Info("Received shutdown signal during startup")
		shutdownAll(entries, shutdownTimeout, logger)
		return nil
	case <-time.After(serverStartTimeout):
		logger.Info("spire-identity-exchange listeners started successfully",
			zap.Strings("listeners", entryNames(entries)))
	}

	select {
	case <-ctx.Done():
		logger.Info("Received shutdown signal")
		shutdownAll(entries, shutdownTimeout, logger)
		return nil

	case serveErr := <-errCh:
		shutdownAll(entries, shutdownTimeout, logger)
		return fmt.Errorf("server runtime error: %w", serveErr)
	}
}

// handleTrustBundleX509 reads instantly from the pre-baked cache on HTTP request hit.
func handleTrustBundleX509(cache *trustBundleCache, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pemBytes := cache.Get()

		if len(pemBytes) == 0 {
			logger.Warn("Trust bundle requested but cache is empty or warming up")
			http.Error(w, "Trust bundle warming up or unavailable", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}
}

// x509SVIDResponse is the JSON body returned by POST /api/v1/svid/{stack}/x509.
type x509SVIDResponse struct {
	SpiffeID  string `json:"spiffeId"`
	Cert      string `json:"cert"`      // PEM, leaf first
	Key       string `json:"key"`       // PEM-encoded PKCS#8 private key
	Bundle    string `json:"bundle"`    // PEM, trust bundle
	ExpiresAt int64  `json:"expiresAt"` // Unix seconds
}

// handleGetX509SVID validates the bearer token, derives selectors via the
// stack's SelectorGenerator, fetches an SVID via the delegated client, and
// returns it as JSON.
//
// Error mapping:
//   - missing/malformed Authorization header → 401
//   - unknown {stack} path-param             → 400
//   - token rejected by validator            → 401
//   - validator returned no selectors        → 400
//   - delegated client found no matching entry → 404
//   - delegated client unavailable / denied  → 503
//   - any other error                        → 500
func handleGetX509SVID(cfg *config.SpireIdentityExchangeConfig, cache *trustBundleCache, dc *delegated.Client, pr *validator.PurposeResolver, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		stack := r.PathValue("stack")
		if stack == "" {
			http.Error(w, "Stack parameter is missing", http.StatusBadRequest)
			return
		}
		v, exists := cfg.Auth.LoadedStacks[stack]
		if !exists {
			http.Error(w, fmt.Sprintf("Unknown stack: %q", stack), http.StatusBadRequest)
			return
		}

		claims, err := v.Validate(r.Context(), token, pr.X509())
		if err != nil {
			logger.Info("token validation failed", zap.String("stack", stack), zap.Error(err))
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		selectors := buildDelegatedSelectors(v, claims, stack)
		if len(selectors) == 0 {
			http.Error(w, "No selectors derivable from token claims", http.StatusBadRequest)
			return
		}

		svid, err := dc.FetchX509SVID(r.Context(), selectors)
		switch {
		case errors.Is(err, delegated.ErrNoMatchingEntry):
			logger.Info("no entry matched selectors",
				zap.String("stack", stack),
				zap.Int("selector_count", len(selectors)),
				zap.Any("selectors", debugSelectors(selectors)))
			http.Error(w, "No registration entry matches the validated identity", http.StatusNotFound)
			return
		case errors.Is(err, delegated.ErrPermissionDenied):
			logger.Error("delegated API rejected this exchange — check authorized_delegates", zap.Error(err))
			http.Error(w, "Delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, delegated.ErrUnavailable):
			logger.Error("delegated API unavailable", zap.Error(err))
			http.Error(w, "Delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, delegated.ErrInvalidArgument):
			// The agent rejected the selectors as malformed. SIE built the
			// selectors from claims it just validated, so this is a server-side
			// bug, not a client request error — 500, log the agent's reason.
			logger.Error("delegated API rejected selectors as invalid",
				zap.String("stack", stack),
				zap.Any("selectors", debugSelectors(selectors)),
				zap.Error(err))
			http.Error(w, "Issuance failed", http.StatusInternalServerError)
			return
		case err != nil:
			logger.Error("delegated svid fetch failed", zap.Error(err))
			http.Error(w, "Issuance failed", http.StatusInternalServerError)
			return
		}

		// Refuse to return a partial response: clients need the bundle to chain-validate
		// the cert, so an empty bundle would leave them unable to use the SVID.
		bundle := cache.Get()
		if len(bundle) == 0 {
			logger.Warn("SVID issued but trust bundle cache is empty or warming up")
			http.Error(w, "Trust bundle warming up or unavailable", http.StatusServiceUnavailable)
			return
		}

		resp := x509SVIDResponse{
			SpiffeID:  svid.SpiffeID,
			Cert:      encodeCertChainPEM(svid.CertChain),
			Key:       encodePKCS8KeyPEM(svid.PrivateKey),
			Bundle:    string(bundle),
			ExpiresAt: svid.ExpiresAt.Unix(),
		}
		// The response body contains a private key. Forbid every layer of
		// caching: TLS-terminating proxies, CDNs, and the client's own disk
		// cache must not retain this material.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		params := r.URL.Query()
		format := params.Get("format")
		switch format {
		case "spiffe-fd-tar":
			w.Header().Set("Content-Type", "application/x-tar")
			t, err := createInMemTar(cfg.SPIRE.TrustDomain, resp.Key + resp.Cert, resp.Bundle)
			if err != nil {
				logger.Error("response tar failed", zap.Error(err))
				http.Error(w, "tarring failed", http.StatusInternalServerError)
			} else {
				w.Write(t)
			}
		case "spire-identity-exchange-json", "":
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(&resp); err != nil {
				logger.Error("response encode failed", zap.Error(err))
				http.Error(w, "encoding failed", http.StatusInternalServerError)
			}
		default:
			logger.Error("response encode failed")
			http.Error(w, "Invalid format", http.StatusBadRequest)
		}
	}
}

// jwtSVIDRequest is the JSON body expected by POST /api/v1/svid/{stack}/jwt.
type jwtSVIDRequest struct {
	Audiences []string `json:"audiences"`
}

// jwtSVIDResponse is the JSON body returned by POST /api/v1/svid/{stack}/jwt.
type jwtSVIDResponse struct {
	SpiffeID  string `json:"spiffeId"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"` // Unix seconds
}

// handleGetJWTSVID validates the bearer token, derives selectors via the
// stack's SelectorGenerator, fetches a JWT-SVID via the delegated client for
// the requested audiences, and returns it as JSON.
//
// Error mapping mirrors handleGetX509SVID:
//   - missing/malformed Authorization header  → 401
//   - unknown {stack} path-param              → 400
//   - malformed body / empty audiences        → 400
//   - token rejected by validator              → 401
//   - validator returned no selectors          → 400
//   - delegated client found no matching entry → 404
//   - delegated client unavailable / denied    → 503
//   - any other error                          → 500
func handleGetJWTSVID(cfg *config.SpireIdentityExchangeConfig, dc *delegated.Client, pr *validator.PurposeResolver, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		stack := r.PathValue("stack")
		if stack == "" {
			http.Error(w, "Stack parameter is missing", http.StatusBadRequest)
			return
		}
		v, exists := cfg.Auth.LoadedStacks[stack]
		if !exists {
			http.Error(w, fmt.Sprintf("Unknown stack: %q", stack), http.StatusBadRequest)
			return
		}

		var req jwtSVIDRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, "Malformed request body", http.StatusBadRequest)
			return
		}
		if len(req.Audiences) == 0 {
			http.Error(w, "audiences must be non-empty", http.StatusBadRequest)
			return
		}

		claims, err := v.Validate(r.Context(), token, pr.JWT(req.Audiences))
		if err != nil {
			logger.Info("token validation failed", zap.String("stack", stack), zap.Error(err))
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		selectors := buildDelegatedSelectors(v, claims, stack)
		if len(selectors) == 0 {
			http.Error(w, "No selectors derivable from token claims", http.StatusBadRequest)
			return
		}

		svid, err := dc.FetchJWTSVID(r.Context(), selectors, req.Audiences)
		switch {
		case errors.Is(err, delegated.ErrNoMatchingEntry):
			logger.Info("no entry matched selectors",
				zap.String("stack", stack),
				zap.Int("selector_count", len(selectors)),
				zap.Any("selectors", debugSelectors(selectors)))
			http.Error(w, "No registration entry matches the validated identity", http.StatusNotFound)
			return
		case errors.Is(err, delegated.ErrPermissionDenied):
			logger.Error("delegated API rejected this exchange — check authorized_delegates", zap.Error(err))
			http.Error(w, "Delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, delegated.ErrUnavailable):
			logger.Error("delegated API unavailable", zap.Error(err))
			http.Error(w, "Delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, delegated.ErrInvalidArgument):
			// SIE built the selectors from claims it just validated, so a
			// rejection here is a server-side bug, not a client request error.
			logger.Error("delegated API rejected selectors as invalid",
				zap.String("stack", stack),
				zap.Any("selectors", debugSelectors(selectors)),
				zap.Error(err))
			http.Error(w, "Issuance failed", http.StatusInternalServerError)
			return
		case err != nil:
			logger.Error("delegated svid fetch failed", zap.Error(err))
			http.Error(w, "Issuance failed", http.StatusInternalServerError)
			return
		}

		resp := jwtSVIDResponse{
			SpiffeID:  svid.SpiffeID,
			Token:     svid.Token,
			ExpiresAt: svid.ExpiresAt.Unix(),
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			logger.Error("response encode failed", zap.Error(err))
			http.Error(w, "encoding failed", http.StatusInternalServerError)
		}
	}
}

func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("Missing Authorization header")
	}
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", errors.New("Invalid Authorization header format")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", errors.New("Empty bearer token")
	}
	return token, nil
}

// encodeCertChainPEM concatenates the DER-encoded chain into a multi-block
// PEM bundle, leaf first.
func encodeCertChainPEM(chain [][]byte) string {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}
	return string(out)
}

// encodePKCS8KeyPEM wraps the PKCS#8 DER-encoded private key the agent
// returns into a PEM block. PKCS#8 covers ECDSA, RSA, and Ed25519.
func encodePKCS8KeyPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

func debugSelectors(selectors []*types.Selector) []string {
	out := make([]string, 0, len(selectors))
	for _, s := range selectors {
		out = append(out, s.Type+":"+s.Value)
	}
	return out
}

func createInMemTar(trustDomain string, certData string, bundleData string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := []struct {
		Name    string
		Content string
		Mode    int64
	}{
		{"x509/0/credential-bundle.pem", certData, 0600},
		{"x509/0/" + trustDomain + ".spiffe-trust-bundle.pem", bundleData, 0644},
	}
	for _, file := range files {
		body := []byte(file.Content)
		hdr := &tar.Header{
			Name:    file.Name,
			Mode:    file.Mode,
			Size:    int64(len(body)),
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("failed to write header for %s: %w", file.Name, err)
		}
		if _, err := tw.Write(body); err != nil {
			return nil, fmt.Errorf("failed to write content for %s: %w", file.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}
	return buf.Bytes(), nil
}

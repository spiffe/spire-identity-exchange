package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	server_util "github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

const (
	shutdownTimeout    = 5 * time.Second
	serverStartTimeout = 10 * time.Second

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

// Run runs spire-identity-exchange gRPC server (and optionally HTTP REST server) and waits for
// termination signals. Pass nil for a validator to disable that auth method.
// Returns the first error encountered during startup or runtime so the caller can exit
// non-zero — a swallowed bind/TLS failure looks identical to a clean shutdown to a
// supervisor and would mask broken deployments.
func Run(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient server_util.ServerClient,
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
	spireClient server_util.ServerClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}

	// Fail fast if both servers are intentionally or accidentally disabled
	if cfg.Server.Port == 0 && cfg.Server.RestPort == 0 {
		return fmt.Errorf("both gRPC (port %d) and REST (port %d) servers are disabled; nothing to run", cfg.Server.Port, cfg.Server.RestPort)
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

	handler, err := NewGRPCHandler(spireClient, cfg, githubOIDCValidator, k8sSATokenValidator, metrics, logger)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server handler: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	errCh := make(chan error, 3)

	// --- gRPC server ---
	var grpcServer *grpc.Server
	var listener net.Listener

	if cfg.Server.Port != 0 {
		logger.Info("Starting spire-identity-exchange gRPC server", zap.Int("port", cfg.Server.Port))

		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
		if err != nil {
			return fmt.Errorf("failed to create network listener: %w", err)
		}

		grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
		logger.Info("gRPC server configured with TLS",
			zap.String("cert_file", cfg.Server.TLS.CertFile),
			zap.String("key_file", cfg.Server.TLS.KeyFile))

		proto.RegisterSpireIdentityExchangeApiServer(grpcServer, handler)
		reflection.Register(grpcServer)

		go func() {
			errCh <- grpcServer.Serve(listener)
		}()
	} else {
		logger.Info("gRPC server port is 0; gRPC server is disabled.")
	}

	// --- REST server ---
	var (
		httpServer      *http.Server
		delegatedClient *delegated.Client
	)
	if cfg.Server.RestPort != 0 {
		// Build all REST deps before spawning the watcher goroutine — otherwise an
		// error from a later init step (e.g. delegated.New) returns with the watcher
		// still running and wlaClient never explicitly closed; the goroutine only
		// unwinds on context cancellation, which leaks an FD/goroutine in any caller
		// that doesn't cancel ctx on the error path (notably tests).
		logger.Info("connecting to delegated identity socket", zap.String("socket_path", cfg.SPIRE.AgentDelegatedSocketPath))
		delegatedClient, err = delegated.New(cfg.SPIRE.AgentDelegatedSocketPath)
		if err != nil {
			return fmt.Errorf("failed to create delegated identity client: %w", err)
		}

		// Trust bundle cache fed by Main agent's Workload API.
		cache := &trustBundleCache{logger: logger}
		socketAddr := "unix://" + cfg.SPIRE.AgentWorkloadSocketPath
		logger.Info("initializing workload API watcher", zap.String("socket_path", socketAddr))

		wlaClient, err := workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
		if err != nil {
			_ = delegatedClient.Close()
			return fmt.Errorf("failed to create workload API client: %w", err)
		}
		go func() {
			defer wlaClient.Close()
			if watchErr := wlaClient.WatchX509Context(ctx, cache); watchErr != nil {
				logger.Error("workload API watcher stopped with error", zap.Error(watchErr))
			}
		}()

		mux := http.NewServeMux()
		mux.HandleFunc("GET /api/v1/trustbundle/x509", handleTrustBundleX509(cache, logger))
		purposeResolver := validator.NewPurposeResolver(validator.PurposeMode(cfg.PurposeMode))
		mux.HandleFunc("POST /api/v1/svid/{stack}/x509", handleGetX509SVID(cfg, cache, delegatedClient, purposeResolver, logger))

		httpServer = &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Server.RestPort),
			Handler:           http.MaxBytesHandler(mux, httpMaxRequestBodyBytes),
			TLSConfig:         tlsConfig.Clone(),
			ReadHeaderTimeout: httpReadHeaderTimeout,
			ReadTimeout:       httpReadTimeout,
			WriteTimeout:      httpWriteTimeout,
			IdleTimeout:       httpIdleTimeout,
		}
		go func() {
			if err := httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}()
		logger.Info("HTTP REST server configured with TLS",
			zap.Int("port", cfg.Server.RestPort),
			zap.String("cert_file", cfg.Server.TLS.CertFile),
			zap.String("key_file", cfg.Server.TLS.KeyFile))
	} else {
		logger.Info("HTTP REST server port is 0; REST server is disabled.")
	}

	// stopStarted tears down anything we already brought up. Used when one server fails to
	// start while the other is already listening — without this, a bind failure on the HTTP
	// REST server would leak the gRPC listener (port stays bound, supervisor restarts re-fail).
	stopStarted := func() {
		if grpcServer != nil {
			grpcServer.Stop()
		}
		if httpServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = httpServer.Shutdown(shutdownCtx)
		}
		if delegatedClient != nil {
			_ = delegatedClient.Close()
		}
	}

	// Give servers a moment to start; surface any immediate bind/listen errors.
	select {
	case err := <-errCh:
		stopStarted()
		if err != nil {
			return fmt.Errorf("failed to start server: %w", err)
		}
		return nil
	case <-time.After(serverStartTimeout):
		logger.Info("spire-identity-exchange servers started successfully",
			zap.Int("grpc_port", cfg.Server.Port),
			zap.Int("http_rest_port", cfg.Server.RestPort))
	}

	select {
	case <-ctx.Done():
		logger.Info("Received shutdown signal")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		stopped := make(chan struct{})
		go func() {
			var wg sync.WaitGroup
			if grpcServer != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					grpcServer.GracefulStop()
				}()
			}
			if httpServer != nil {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = httpServer.Shutdown(shutdownCtx)
				}()
			}
			wg.Wait()
			close(stopped)
		}()

		select {
		case <-stopped:
			logger.Info("Server shutdown completed")
		case <-shutdownCtx.Done():
			logger.Warn("Shutdown timeout exceeded, forcing stop")
			if grpcServer != nil {
				grpcServer.Stop()
			}
		}

		if delegatedClient != nil {
			_ = delegatedClient.Close()
		}
		return nil

	case err := <-errCh:
		return fmt.Errorf("server runtime error: %w", err)
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

		selectors := v.GenerateSelectors(claims)
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
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			logger.Error("response encode failed", zap.Error(err))
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

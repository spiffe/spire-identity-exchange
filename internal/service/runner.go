package service

import (
	"context"
	"encoding/json"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
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
func (c *trustBundleCache) OnX509ContextWatchError(err error) {
	// Hooks error channel updates from the streaming socket connection context gracefully
}

// Run runs spire-identity-exchange gRPC server (and optionally HTTP gateway) and waits for
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

	// --- Initialize go-spiffe background watcher stream ---
	cache := &trustBundleCache{}
	if cfg.Server.RestPort != 0 {
		socketAddr := fmt.Sprintf("unix://%s", cfg.SPIRE.AgentWorkloadSocketPath)
		logger.Info("Initializing go-spiffe workload API stream client", zap.String("socket_path", socketAddr))

		client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
		if err != nil {
			return fmt.Errorf("failed to create workload API client: %w", err)
		}

		go func() {
			defer client.Close()
			if watchErr := client.WatchX509Context(ctx, cache); watchErr != nil {
				logger.Error("SPIRE trust bundle context watcher runtime error", zap.Error(watchErr))
			}
		}()
	}

	// --- Custom Hand-Crafted REST API ---
	var httpServer *http.Server
	if cfg.Server.RestPort != 0 {
		mux := http.NewServeMux()

		mux.HandleFunc("GET /api/v1/trustbundle/x509", handleTrustBundleX509(cache, logger))
		mux.HandleFunc("POST /api/v1/svid/{plugin}/x509", handleGetX509SVID(cache, logger))

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
	// gateway would leak the gRPC listener (port stays bound, supervisor restarts re-fail).
	stopStarted := func() {
		if grpcServer != nil {
			grpcServer.Stop()
		}
		if httpServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			_ = httpServer.Shutdown(shutdownCtx)
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
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBytes)
	}
}

// handleGetX509SVID Verify the token from the user and return 1 valid x509 svid if available including chain
func handleGetX509SVID(cache *trustBundleCache, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		//w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Type", "plain/text")
		w.WriteHeader(http.StatusOK)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization Header", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			http.Error(w, "Invalid Authorization Header Format", http.StatusUnauthorized)
			return
		}

		token := strings.TrimSpace(authHeader[7:])
		if token == "" {
			http.Error(w, "Empty Token", http.StatusUnauthorized)
			return
		}

		cfg := github.Config{
			AllowedRepositories: []string{"spiffe/spire-identity-exchange"},
			Audiences:           []string{"spire-identity-exchange"},
		}

		validator, err := github.NewValidator(cfg)
		if err != nil {
			logger.Warn("Failed to init validator", zap.Error(err))
			http.Error(w, "spire-identity-exchange is currently unavailable", http.StatusServiceUnavailable)
			return
		}
		claims, err := validator.Validate(r.Context(), token)
		if err != nil {
			logger.Info("Failed to validate", zap.Error(err))
			http.Error(w, "Failed to validate your token", http.StatusUnauthorized)
			return
		}
		selectors := validator.GenerateSelectors(claims)
		selectorsJSON, _ := json.Marshal(selectors)
		_, _ = w.Write([]byte("Hello: " + r.PathValue("plugin") + " " + string(selectorsJSON) + "\n"))
	}
}

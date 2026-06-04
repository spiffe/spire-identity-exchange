package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	proto "github.com/spiffe/spire-identity-exchange/api"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/service/rest"
	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	"github.com/spiffe/spire-identity-exchange/internal/validator"
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

// RESTDeps holds the dependencies the REST surface needs that are constructed
// in main.go (validators come from operator config; the delegated client
// needs a live socket path). Passing them through Run keeps runner.go a pure
// lifecycle file.
type RESTDeps struct {
	// Plugins maps a path-param name (e.g. "github") to a validator + selector
	// generator pair. Population happens in main.go from operator config.
	Plugins rest.PluginSet
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
	restDeps RESTDeps,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	if err := runSpireIdentityExchangeServer(ctx, cfg, spireClient, githubOIDCValidator, k8sSATokenValidator, restDeps, metrics, logger); err != nil {
		logger.Error("spire-identity-exchange error", zap.Error(err))
		return err
	}
	logger.Info("spire-identity-exchange server stopped gracefully")
	return nil
}

// runSpireIdentityExchangeServer starts the gRPC server and, if restPort is set,
// also an HTTP REST server on a separate port backed by handlers in the rest package.
func runSpireIdentityExchangeServer(
	ctx context.Context,
	cfg *config.SpireIdentityExchangeConfig,
	spireClient server_util.ServerClient,
	githubOIDCValidator validator.TokenValidator,
	k8sSATokenValidator validator.TokenValidator,
	restDeps RESTDeps,
	metrics metrics.Metrics,
	logger *zap.Logger,
) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	logger.Info("Starting spire-identity-exchange gRPC server", zap.Int("port", cfg.Server.Port))

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

	// --- gRPC server ---
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.Port))
	if err != nil {
		return fmt.Errorf("failed to create network listener: %w", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	logger.Info("gRPC server configured with TLS",
		zap.String("cert_file", cfg.Server.TLS.CertFile),
		zap.String("key_file", cfg.Server.TLS.KeyFile))

	proto.RegisterSpireIdentityExchangeApiServer(grpcServer, handler)
	reflection.Register(grpcServer)

	errCh := make(chan error, 3)
	go func() {
		errCh <- grpcServer.Serve(listener)
	}()

	// --- REST server (optional) ---
	var (
		httpServer      *http.Server
		delegatedClient *delegated.Client
	)
	if cfg.Server.RestPort != 0 {
		// Trust bundle cache fed by Main agent's Workload API.
		trustBundle := rest.NewTrustBundleCache(logger)
		socketAddr := "unix://" + cfg.SPIRE.AgentWorkloadSocketPath
		logger.Info("initializing workload API watcher", zap.String("socket_path", socketAddr))

		wlaClient, err := workloadapi.New(ctx, workloadapi.WithAddr(socketAddr))
		if err != nil {
			return fmt.Errorf("failed to create workload API client: %w", err)
		}
		go func() {
			defer wlaClient.Close()
			if watchErr := wlaClient.WatchX509Context(ctx, trustBundle); watchErr != nil {
				logger.Error("workload API watcher stopped with error", zap.Error(watchErr))
			}
		}()

		// Delegated Identity client to SIX's admin socket.
		logger.Info("connecting to delegated identity socket", zap.String("socket_path", cfg.SPIRE.AgentDelegatedSocketPath))
		delegatedClient, err = delegated.New(cfg.SPIRE.AgentDelegatedSocketPath)
		if err != nil {
			return fmt.Errorf("failed to create delegated identity client: %w", err)
		}

		mux := rest.NewMux(rest.Deps{
			TrustBundle: trustBundle,
			Delegated:   delegatedClient,
			Plugins:     restDeps.Plugins,
			Logger:      logger,
		})

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
	}

	// stopStarted tears down anything we already brought up. Used when one server fails to
	// start while the other is already listening — without this, a bind failure on the HTTP
	// REST server would leak the gRPC listener (port stays bound, supervisor restarts re-fail).
	stopStarted := func() {
		grpcServer.Stop()
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
			wg.Add(1)
			go func() {
				defer wg.Done()
				grpcServer.GracefulStop()
			}()
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
			grpcServer.Stop()
		}

		if delegatedClient != nil {
			_ = delegatedClient.Close()
		}
		return nil

	case err := <-errCh:
		return fmt.Errorf("server runtime error: %w", err)
	}
}

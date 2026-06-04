package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	githuboidc "github.com/spiffe/spire-identity-exchange/internal/github-oidc"
	k8ssatoken "github.com/spiffe/spire-identity-exchange/internal/k8s-sa-token"
	"github.com/spiffe/spire-identity-exchange/internal/cache"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/service"
	"github.com/spiffe/spire-identity-exchange/internal/validator"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

// run holds the entire main body so deferred cleanup (logger Sync, SPIRE client Release,
// signal context stop) runs on error paths too. main() calls os.Exit only after run
// returns, never inline — os.Exit bypasses defers.
func run() error {
	// Bootstrap logger for config loading; gets replaced once cfg.LogLevel is known.
	rawLogger, err := zap.NewProduction()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	// Closure (not `defer rawLogger.Sync()`) so a later reassignment of rawLogger —
	// when cfg.LogLevel rebuilds the logger — still gets Sync'd at return.
	defer func() { _ = rawLogger.Sync() }()
	logger := *rawLogger

	// Parse configuration from flags
	cfg, err := parseFlags(&logger)
	if err != nil {
		return err
	}

	// Honor cfg.LogLevel. Config validation has already rejected unsupported strings,
	// so UnmarshalText here is safe; empty defaults to info via the bootstrap logger.
	if cfg.LogLevel != "" {
		var level zapcore.Level
		if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
			return fmt.Errorf("invalid logLevel %q: %w", cfg.LogLevel, err)
		}
		prodCfg := zap.NewProductionConfig()
		prodCfg.Level = zap.NewAtomicLevelAt(level)
		newLogger, err := prodCfg.Build()
		if err != nil {
			return fmt.Errorf("failed to reconfigure logger at level %q: %w", cfg.LogLevel, err)
		}
		rawLogger = newLogger
		logger = *rawLogger
	}

	// Create SPIRE client
	socketPath := cfg.SPIRE.UnixSocketPath
	if socketPath == "" {
		logger.Error("unix_socket_path is required")
		return fmt.Errorf("unix_socket_path is required")
	}

	spireClient, err := util.NewServerClient(&net.UnixAddr{
		Name: socketPath,
		Net:  "unix",
	})
	if err != nil {
		logger.Error("failed to connect to SPIRE server via Unix socket", zap.Error(err))
		return err
	}
	defer spireClient.Release()

	// Initialize metrics (includes process and Go runtime metrics)
	metricsServer := prommetrics.NewMetricsServer(
		prommetrics.WithPort(cfg.Server.MetricsPort),
	)
	appMetrics := prommetrics.NewPluginMetrics(metricsServer.Registry, "spire_identity_exchange")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start metrics server in background. A bind/serve failure is logged but not fatal —
	// the core gRPC service can continue to operate without /metrics.
	go func() {
		if err := metricsServer.For("spire-identity-exchange", appMetrics).Start(ctx, &logger); err != nil {
			logger.Error("metrics server stopped with error", zap.Error(err))
		}
	}()
	logger.Info("Metrics server initialized with runtime metrics", zap.Int("port", cfg.Server.MetricsPort))

	var githubOIDCValidator validator.TokenValidator
	var k8sSATokenValidator validator.TokenValidator

	// Only initialize validators if the gRPC server is enabled (port != 0)
	if cfg.Server.Port != 0 {
		// Create GitHub OIDC validator if enabled
		if cfg.GitHubOIDC.Enabled {
			v, err := githuboidc.NewValidator(ctx, cfg.GitHubOIDC, appMetrics, &logger)
			if err != nil {
				logger.Error("failed to create GitHub OIDC validator", zap.Error(err))
				return err
			}
			// In-memory replay cache only protects against replay within this process. Multi-replica
			// deployments need a shared backend (e.g. Redis) — a workload could otherwise replay the
			// same token against a different replica. For now operators running >1 replica must
			// serialize through a single instance, gate load-balancing to sticky routing, or accept
			// the risk.
			//
			// TODO(replay-cache-backend): implement a pluggable ReplayCache backend (Redis first).
			//   - Add a `replayCache` block to SpireIdentityExchangeConfig (kind: memory|redis, addr,
			//     password, db, key prefix, ttl).
			//   - Implement RedisReplayCache satisfying the existing cache.ReplayCache interface.
			//   - Wire selection here based on cfg.ReplayCache.Kind; default remains in-memory.
			//   - Add integration tests with miniredis. Cross-replica replay rejection must be
			//     verified end-to-end (two SIE instances + one shared Redis).
			//   - Drop the WARN log below once a shared backend is configured.
			githubOIDCValidator = cache.NewReplayCheckingValidator(v, cache.NewInMemoryReplayCache(ctx))
			logger.Info("GitHub OIDC validator enabled with in-memory replay cache")
			logger.Warn("replay cache is in-memory only: multi-replica deployments can be bypassed by replaying a token against a different replica. Run a single replica until a shared backend is configured.")
		}

		// Create K8s SA token validator if enabled
		if cfg.K8sSAToken.Enabled {
			v, err := k8ssatoken.NewValidator(cfg.K8sSAToken, &logger)
			if err != nil {
				logger.Error("failed to create K8s SA token validator", zap.Error(err))
				return err
			}
			k8sSATokenValidator = v
			logger.Info("Kubernetes SA token validator enabled")
		}

		if githubOIDCValidator == nil && k8sSATokenValidator == nil {
			logger.Error("at least one authentication method must be enabled (githubOIDC or k8sSAToken)")
			return fmt.Errorf("no authentication method enabled")
		}
	} else {
		logger.Info("gRPC port is 0; skipping token validator initializations")
	}

	return service.Run(ctx, cfg, spireClient, githubOIDCValidator, k8sSATokenValidator, appMetrics, &logger)
}

func parseFlags(logger *zap.Logger) (*config.SpireIdentityExchangeConfig, error) {
	configFile := flag.String("config", "", "Path to spire-identity-exchange JSON configuration file")
	expandEnv := flag.Bool("expand-env", false, "Expand environment variables in config file")

	flag.Parse()

	if *configFile == "" {
		logger.Error("--config flag is required")
		return nil, fmt.Errorf("--config flag is required")
	}

	cfg, err := loadSpireIdentityExchangeConfigFile(*configFile, expandEnv != nil && *expandEnv)
	if err != nil {
		logger.Error("failed to load spire-identity-exchange configuration", zap.String("file", *configFile), zap.Error(err))
		return nil, err
	}

	logger.Info("spire-identity-exchange configuration file is loaded", zap.String("file", *configFile), zap.Any("config", cfg))
	return cfg, nil
}

// loadSpireIdentityExchangeConfigFile loads spire-identity-exchange configuration from a JSON file
func loadSpireIdentityExchangeConfigFile(filePath string, expandEnv bool) (*config.SpireIdentityExchangeConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the file %s: %w", filePath, err)
	}

	if expandEnv {
		data = []byte(os.ExpandEnv(string(data)))
	}

	var cfg config.SpireIdentityExchangeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the file %s: %w", filePath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate the configuration: %w", err)
	}

	return &cfg, nil
}

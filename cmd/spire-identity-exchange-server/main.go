package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/service"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
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

  spireClient, err := createSpireClient(cfg, &logger)
  if err != nil {
  	return err
  }
  if spireClient != nil {
  	defer spireClient.Release()
  }

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

	githubOIDCValidator, k8sSATokenValidator, err := createLegacyValidators(ctx, cfg, appMetrics, &logger)
	if err != nil {
		return err
	}

	// Only initialize validators if the gRPC server is enabled (port != 0)
	if cfg.Server.Port != 0 {
		if githubOIDCValidator == nil && k8sSATokenValidator == nil && len(cfg.Auth.Plugins) == 0 {
			logger.Error("at least one authentication method must be enabled")
			return fmt.Errorf("no authentication method enabled")
		}

	} else {
		logger.Info("gRPC port is 0; skipping token validator initializations")
	}

	// REST surface reads pkg/validator instances directly off cfg.Auth.LoadedStacks
	// (the delegated path needs GenerateSelectors, which only pkg/validator exposes).
	// The internal/ validators above remain in use by the gRPC broker path.
	//
	// TODO: replay-cache wrap the pkg/validator instances too. The existing
	// internal/cache.NewReplayCheckingValidator wraps the internal validator
	// interface; equivalent wrapping for the pkg validator is a follow-up.
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the file %s: %w", filePath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("failed to validate the configuration: %w", err)
	}

	// Load the plugins and stacks from validated config
	cfg.Auth.LoadedPlugins = make(map[string]validator.TokenValidatorAndSelectorGenerator)
	cfg.Auth.LoadedStacks = make(map[string]validator.TokenValidatorAndSelectorGenerator)
	for _, plugin := range cfg.Auth.Plugins {
		if plugin.Config == nil {
			return nil, fmt.Errorf("plugin %q has no loaded config", plugin.Name)
		}
		v, err := plugin.Config.NewValidator()
		if err != nil {
			return nil, fmt.Errorf("failed to create validator for plugin %q: %w", plugin.Name, err)
		}
		cfg.Auth.LoadedPlugins[plugin.Name] = v
		cfg.Auth.LoadedStacks[plugin.Name] = v
	}

	return &cfg, nil
}

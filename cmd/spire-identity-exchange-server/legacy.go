//go:build legacy

package main

import (
	"context"
	"fmt"
	"net"

	githuboidc "github.com/spiffe/spire-identity-exchange/internal/github-oidc"
	k8ssatoken "github.com/spiffe/spire-identity-exchange/internal/k8s-sa-token"
	"github.com/spiffe/spire-identity-exchange/internal/cache"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/service"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire/cmd/spire-server/util"
	"go.uber.org/zap"
)

func createSpireClient(cfg *config.SpireIdentityExchangeConfig, logger *zap.Logger) (service.SpireClient, error) {
	socketPath := cfg.SPIRE.UnixSocketPath
	if cfg.Server.TLS.GRPC.Enabled() && (cfg.GitHubOIDC.Enabled || cfg.K8sSAToken.Enabled) {
		if socketPath == "" {
			logger.Error("unix_socket_path is required")
			return nil, fmt.Errorf("unix_socket_path is required")
		}
		spireClient, err := util.NewServerClient(&net.UnixAddr{
			Name: socketPath,
			Net:  "unix",
		})
		if err != nil {
			logger.Error("failed to connect to SPIRE server via Unix socket", zap.Error(err))
			return nil, err
		}
		return spireClient, nil
	}
	return nil, nil
}

func createLegacyValidators(ctx context.Context, cfg *config.SpireIdentityExchangeConfig, appMetrics *prommetrics.PluginMetrics, logger *zap.Logger) (validator.TokenValidator, validator.TokenValidator, error) {
	var githubOIDCValidator validator.TokenValidator
	var k8sSATokenValidator validator.TokenValidator

	if cfg.Server.TLS.GRPC.Enabled() {
		if cfg.GitHubOIDC.Enabled {
			v, err := githuboidc.NewValidator(ctx, cfg.GitHubOIDC, appMetrics, logger)
			if err != nil {
				logger.Error("failed to create GitHub OIDC validator", zap.Error(err))
				return nil, nil, err
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

		if cfg.K8sSAToken.Enabled {
			v, err := k8ssatoken.NewValidator(cfg.K8sSAToken, logger)
			if err != nil {
				logger.Error("failed to create K8s SA token validator", zap.Error(err))
				return nil, nil, err
			}
			k8sSATokenValidator = v
			logger.Info("Kubernetes SA token validator enabled")
		}
	}

	return githubOIDCValidator, k8sSATokenValidator, nil
}

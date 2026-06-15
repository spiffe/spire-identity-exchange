//go:build !legacy

package main

import (
	"context"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	prommetrics "github.com/spiffe/spire-identity-exchange/internal/metrics/prometheus"
	"github.com/spiffe/spire-identity-exchange/internal/service"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"go.uber.org/zap"
)

func createSpireClient(*config.SpireIdentityExchangeConfig, *zap.Logger) (service.SpireClient, error) {
	return nil, nil
}

func createLegacyValidators(context.Context, *config.SpireIdentityExchangeConfig, *prommetrics.PluginMetrics, *zap.Logger) (validator.TokenValidator, validator.TokenValidator, error) {
	return nil, nil, nil
}

package k8ssatoken

import (
	"context"
	"testing"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewValidator(t *testing.T) {
	logger := zap.NewNop()

	testCases := []struct {
		name      string
		config    config.K8sSATokenConfig
		expectErr bool
	}{
		{
			name: "missing apiHost rejected",
			config: config.K8sSATokenConfig{
				TLS: config.K8sAPIClientTlsConfig{},
			},
			expectErr: true,
		},
		{
			name: "minimum required: apiHost set",
			config: config.K8sSATokenConfig{
				APIHost: "https://kubernetes.default.svc:443",
			},
			expectErr: false,
		},
		{
			name: "with audiences configured",
			config: config.K8sSATokenConfig{
				APIHost:   "https://kubernetes.default.svc:443",
				Audiences: []string{"spire-identity-exchange"},
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, err := NewValidator(tc.config, logger)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, val)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, val)
		})
	}
}

func TestValidateToken(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.K8sSATokenConfig{
		APIHost: "https://kubernetes.default.svc:443",
	}

	val, err := NewValidator(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	testCases := []struct {
		name      string
		token     string
		expectErr bool
	}{
		{
			name:      "empty token",
			token:     "",
			expectErr: true,
		},
		{
			name:      "invalid JWT token",
			token:     "invalid.jwt.token",
			expectErr: true,
		},
	}

	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenInfo, err := val.Validate(ctx, tc.token, validator.X509Purpose())

			if tc.expectErr && err == nil {
				assert.Error(t, err, "expected error but got none")
			}

			if !tc.expectErr && err != nil {
				assert.NoError(t, err, "expected no error but got: %v", err)
			}

			if !tc.expectErr && tokenInfo == nil {
				assert.NotNil(t, tokenInfo, "expected token info to be returned")
			}
		})
	}
}

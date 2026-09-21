package spiffe

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticKeyProvider struct {
	keys map[string]crypto.PublicKey
}

func (p *staticKeyProvider) GetKey(_ context.Context, kid string) (crypto.PublicKey, error) {
	key, ok := p.keys[kid]
	if !ok {
		return nil, fmt.Errorf("no key found for kid=%q", kid)
	}
	return key, nil
}

func TestConfig_keySource(t *testing.T) {
	cfg := &Config{}
	assert.Equal(t, KeySourceOIDC, cfg.keySource())

	cfg.KeySource = KeySourceWorkloadAPI
	assert.Equal(t, KeySourceWorkloadAPI, cfg.keySource())
}

func TestConfig_jwksTrustDomain(t *testing.T) {
	cfg := &Config{TrustDomain: "example.org"}
	assert.Equal(t, "example.org", cfg.jwksTrustDomain())

	cfg.JWKSTrustDomain = "peer.example.org"
	assert.Equal(t, "peer.example.org", cfg.jwksTrustDomain())
}

func TestWorkloadSocketAddr(t *testing.T) {
	assert.Equal(t, "unix:///tmp/agent.sock", workloadSocketAddr("/tmp/agent.sock"))
	assert.Equal(t, "unix:///tmp/agent.sock", workloadSocketAddr("unix:///tmp/agent.sock"))
}

func TestNewValidator_withInjectedKeyProvider(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const kid = "test-kid"

	now := time.Now()
	claims := map[string]interface{}{
		"iss": "https://issuer.example.org",
		"sub": "spiffe://example.org/workload/myapp",
		"aud": "spire-server",
		"exp": float64(now.Add(time.Hour).Unix()),
		"jti": "jti-1",
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(claims))
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(privKey)
	require.NoError(t, err)

	cfg := Config{
		IssuerURL:    "https://issuer.example.org",
		Audiences:    []string{"spire-server"},
		TrustDomain:  "example.org",
		PathPatterns: []string{"^/workload/.*"},
		KeySource:    KeySourceWorkloadAPI,
		KeyProvider: &staticKeyProvider{
			keys: map[string]crypto.PublicKey{kid: &privKey.PublicKey},
		},
	}

	v, err := NewValidator(cfg)
	require.NoError(t, err)

	got, err := v.Validate(context.Background(), tokenString, validator.X509Purpose())
	require.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/workload/myapp", got.GetRaw()["sub"])
}

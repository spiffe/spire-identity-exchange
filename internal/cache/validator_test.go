package cache

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeValidator struct {
	claims    v.Claims
	err       error
	callCount int
}

func (f *fakeValidator) Validate(_ context.Context, _ string, _ v.Purpose) (v.Claims, error) {
	f.callCount++
	return f.claims, f.err
}

// fakeJWT builds a minimal JWT token string with the given jti in the payload.
// The signature is not valid, but the structure is enough for extractJTI.
func fakeJWT(jti string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"jti":"%s"}`, jti)))
	return header + "." + payload + ".fakesig"
}

type fakeSyncValidator struct {
	fakeValidator
	started  bool
	startErr error
}

func (f *fakeSyncValidator) Start(_ context.Context) error {
	f.started = true
	return f.startErr
}

func TestStart_DelegatesToInnerKeySynchronizer(t *testing.T) {
	inner := &fakeSyncValidator{}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	syncer := w.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.NoError(t, err)
	assert.True(t, inner.started)
}

func TestStart_NoOpWhenInnerLacksKeySynchronizer(t *testing.T) {
	inner := &fakeValidator{}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	syncer := w.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.NoError(t, err)
}

func TestStart_PropagatesError(t *testing.T) {
	inner := &fakeSyncValidator{startErr: assert.AnError}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	syncer := w.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.ErrorIs(t, err, assert.AnError)
}

func TestValidate_ReplayDetection(t *testing.T) {
	claims := &v.JWTClaims{
		JTI:    "unique-jti-123",
		Expiry: 9999999999,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	purpose := v.X509Purpose()

	// First call should succeed.
	result, err := w.Validate(context.Background(), "token", purpose)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Second call with same purpose should fail (replay).
	_, err = w.Validate(context.Background(), "token", purpose)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
}

func TestValidate_PerPurposeIsolation(t *testing.T) {
	claims := &v.JWTClaims{
		JTI:    "shared-jti-456",
		Expiry: 9999999999,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	x509Purpose := v.X509Purpose()
	jwtPurpose := v.JWTPurpose([]string{"api.example.com"})

	// Same JTI with different purposes should both succeed.
	result1, err := w.Validate(context.Background(), "token", x509Purpose)
	require.NoError(t, err)
	assert.NotNil(t, result1)

	result2, err := w.Validate(context.Background(), "token", jwtPurpose)
	require.NoError(t, err)
	assert.NotNil(t, result2)

	// But repeating the same purpose should fail.
	_, err = w.Validate(context.Background(), "token", x509Purpose)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
}

func TestValidate_MissingJTI(t *testing.T) {
	claims := &v.JWTClaims{
		JTI:    "",
		Expiry: 9999999999,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	_, err := w.Validate(context.Background(), "token", v.X509Purpose())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti")
}

func TestValidate_MissingExpiration(t *testing.T) {
	claims := &v.JWTClaims{
		JTI:    "some-jti",
		Expiry: 0,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	_, err := w.Validate(context.Background(), "token", v.X509Purpose())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestValidate_EarlyReplayRejection(t *testing.T) {
	jti := "early-check-jti"
	claims := &v.JWTClaims{
		JTI:    jti,
		Expiry: 9999999999,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	token := fakeJWT(jti)
	purpose := v.X509Purpose()

	// First call: inner.Validate is called, token accepted.
	result, err := w.Validate(context.Background(), token, purpose)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, inner.callCount)

	// Second call: rejected by the early check before inner.Validate runs.
	_, err = w.Validate(context.Background(), token, purpose)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
	assert.Equal(t, 1, inner.callCount, "inner.Validate should not be called on replay")
}

func TestValidate_EarlyCheckPerPurposeIsolation(t *testing.T) {
	jti := "purpose-iso-jti"
	claims := &v.JWTClaims{
		JTI:    jti,
		Expiry: 9999999999,
		Raw:    map[string]interface{}{},
	}
	inner := &fakeValidator{claims: claims}
	rc := NewInMemoryReplayCache(context.Background())
	w := NewReplayCheckingValidator(inner, rc)

	token := fakeJWT(jti)

	// Use for x509 purpose.
	_, err := w.Validate(context.Background(), token, v.X509Purpose())
	require.NoError(t, err)
	assert.Equal(t, 1, inner.callCount)

	// Same token, different purpose: early check should pass (different cache key).
	_, err = w.Validate(context.Background(), token, v.JWTPurpose([]string{"api.example.com"}))
	require.NoError(t, err)
	assert.Equal(t, 2, inner.callCount)

	// Replay the x509 purpose: rejected early.
	_, err = w.Validate(context.Background(), token, v.X509Purpose())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay detected")
	assert.Equal(t, 2, inner.callCount, "inner.Validate should not be called on replay")
}

func TestExtractJTI(t *testing.T) {
	assert.Equal(t, "my-jti", extractJTI(fakeJWT("my-jti")))
	assert.Equal(t, "", extractJTI("not-a-jwt"))
	assert.Equal(t, "", extractJTI("header.!!!invalid-base64.sig"))
	assert.Equal(t, "", extractJTI(""))
}

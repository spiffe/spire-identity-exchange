package cache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	v "github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// minReplayRetention is the floor for how long a jti stays in the replay cache. The
// per-token expiry from the JWT's exp claim is normally fine, but when token expiry
// validation is disabled (e.g. SkipTokenExpiration during local testing) the exp can
// already be in the past — the eviction loop would then drop the entry almost
// immediately and the same token could be accepted again. This floor guarantees the
// cache retains the jti long enough to actually block a replay.
const minReplayRetention = 5 * time.Minute

type replayCheckingValidator struct {
	inner v.TokenValidator
	cache ReplayCache
	now   func() time.Time
}

// NewReplayCheckingValidator wraps inner with replay detection using cache.
// Tokens without a jti claim are rejected.
//
// The replay check runs in two phases:
//
//  1. Early check (before inner validation): the jti is extracted from the
//     unverified JWT payload via lightweight base64 decode. If the jti is
//     already in the cache, the token is rejected immediately without calling
//     inner.Validate. This avoids expensive signature verification and any
//     heavy post-validation work (e.g. cloud metadata lookups) for known
//     replays. Because this phase is read-only, a forged token with a spoofed
//     jti cannot poison the cache.
//
//  2. Post-verification mark (after inner validation): once inner.Validate
//     succeeds, the verified jti is atomically written to the cache via
//     cache.Add. This handles the race where two concurrent requests both
//     pass the early check -- only the first Add wins.
//
// Semantics: single-attempted-use. The jti is recorded on validation success,
// BEFORE the downstream mint runs. A legitimate client whose mint fails must
// obtain a fresh token. OIDC tokens are short-lived and cheap to re-issue,
// so this is the safer default.
func NewReplayCheckingValidator(inner v.TokenValidator, cache ReplayCache) v.TokenValidator {
	return &replayCheckingValidator{inner: inner, cache: cache, now: time.Now}
}

func (r *replayCheckingValidator) Start(ctx context.Context) error {
	if syncer, ok := r.inner.(v.KeySynchronizer); ok {
		return syncer.Start(ctx)
	}
	return nil
}

func (r *replayCheckingValidator) Validate(ctx context.Context, token string, purpose v.Purpose) (v.Claims, error) {
	// Phase 1: early replay rejection using unverified JTI.
	// Read-only cache lookup -- avoids expensive inner.Validate for known replays.
	if jti := extractJTI(token); jti != "" {
		cacheKey := fmt.Sprintf("jti:%s:%s", purpose, jti)
		if r.cache.Contains(cacheKey) {
			return nil, fmt.Errorf("token replay detected: jti %q has already been used for purpose %q", jti, purpose)
		}
	}

	// Phase 2: full verified parse (signature, claims policy, etc.).
	claims, err := r.inner.Validate(ctx, token, purpose)
	if err != nil {
		return nil, err
	}

	jti := claims.GetUniqueID()
	if jti == "" {
		return nil, errors.New("token missing jti claim: replay detection requires a unique token ID")
	}

	expiration := claims.GetExpiration()
	if expiration == 0 {
		return nil, errors.New("token missing exp claim: cannot determine replay cache TTL")
	}

	// Floor the cache expiry at now+minReplayRetention so an exp that's already in the
	// past (only possible when issuer-side expiry checks are disabled) still keeps the
	// jti tracked long enough to actually block a replay.
	retainUntil := time.Unix(expiration, 0)
	if floor := r.now().Add(minReplayRetention); retainUntil.Before(floor) {
		retainUntil = floor
	}

	// Phase 3: atomic check-and-mark with verified JTI.
	// Two concurrent requests could both pass the early check; cache.Add is atomic
	// so only the first caller wins. The same token can legitimately be used for
	// different SVID types (x509, jwt with different audiences) without triggering
	// replay, because the cache key includes the purpose.
	cacheKey := fmt.Sprintf("jti:%s:%s", purpose, jti)
	if !r.cache.Add(cacheKey, retainUntil) {
		return nil, fmt.Errorf("token replay detected: jti %q has already been used for purpose %q", jti, purpose)
	}

	return claims, nil
}

// extractJTI performs a lightweight, unverified extraction of the jti claim
// from a JWT token string by base64-decoding the payload segment. Returns ""
// if the token is not a valid JWT structure or has no jti claim.
func extractJTI(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.JTI
}

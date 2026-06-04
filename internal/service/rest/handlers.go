package rest

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"

	"github.com/spiffe/spire-identity-exchange/internal/spireagent/delegated"
	"go.uber.org/zap"
)

// Deps groups everything the REST handlers need. Keeping it as a struct keeps
// each HandleFunc factory simple (one arg) and makes future additions cheap.
type Deps struct {
	TrustBundle *TrustBundleCache
	Delegated   DelegatedFetcher
	Plugins     PluginSet
	Logger      *zap.Logger
}

// DelegatedFetcher is the subset of *delegated.Client the handlers depend on.
// Defined as an interface so tests can inject a fake without standing up a
// SPIRE agent socket.
type DelegatedFetcher interface {
	FetchX509SVID(ctx context.Context, selectors []*types.Selector) (*delegated.X509SVID, error)
}

// x509SVIDResponse is the JSON body returned by POST /api/v1/svid/{plugin}/x509.
type x509SVIDResponse struct {
	SpiffeID  string `json:"spiffeId"`
	Cert      string `json:"cert"`      // PEM, leaf first
	Key       string `json:"key"`       // PEM-encoded PKCS#8 private key
	Bundle    string `json:"bundle"`    // PEM, trust bundle
	ExpiresAt int64  `json:"expiresAt"` // Unix seconds
}

// HandleTrustBundleX509 returns the cached trust bundle as a PEM file.
// The handler is unauthenticated — trust bundles are public by SPIFFE design.
// Returns 503 during the startup window before the first watcher push lands.
func HandleTrustBundleX509(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pemBytes := d.TrustBundle.Get()
		if len(pemBytes) == 0 {
			d.Logger.Warn("trust bundle requested but cache is empty or warming up")
			http.Error(w, "Trust bundle warming up or unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pemBytes)
	}
}

// HandleGetX509SVID validates the bearer token, derives selectors via the
// plugin's SelectorGenerator, fetches an SVID via the delegated client, and
// returns it as JSON.
//
// Error mapping:
//   - missing/malformed Authorization header → 401
//   - unknown {plugin} path-param            → 400
//   - token rejected by validator            → 401
//   - validator returned no selectors        → 400
//   - delegated client found no matching entry → 404
//   - delegated client unavailable           → 503
//   - any other error                        → 500
func HandleGetX509SVID(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		pluginName := r.PathValue("plugin")
		plugin, ok := d.Plugins.Get(pluginName)
		if !ok {
			http.Error(w, fmt.Sprintf("unknown plugin: %q", pluginName), http.StatusBadRequest)
			return
		}

		claims, err := plugin.Validator.Validate(r.Context(), token)
		if err != nil {
			d.Logger.Info("token validation failed", zap.String("plugin", pluginName), zap.Error(err))
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		selectors := plugin.SelectorGenerator.GenerateSelectors(claims)
		if len(selectors) == 0 {
			http.Error(w, "no selectors derivable from token claims", http.StatusBadRequest)
			return
		}

		svid, err := d.Delegated.FetchX509SVID(r.Context(), selectors)
		switch {
		case errors.Is(err, delegated.ErrNoMatchingEntry):
			d.Logger.Info("no entry matched selectors",
				zap.String("plugin", pluginName),
				zap.Int("selector_count", len(selectors)),
				zap.Any("selectors", debugSelectors(selectors)))
			http.Error(w, "no registration entry matches the validated identity", http.StatusNotFound)
			return
		case errors.Is(err, delegated.ErrPermissionDenied):
			d.Logger.Error("delegated API rejected this exchange — check authorized_delegates", zap.Error(err))
			http.Error(w, "delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case errors.Is(err, delegated.ErrUnavailable):
			d.Logger.Error("delegated API unavailable", zap.Error(err))
			http.Error(w, "delegated issuance unavailable", http.StatusServiceUnavailable)
			return
		case err != nil:
			d.Logger.Error("delegated svid fetch failed", zap.Error(err))
			http.Error(w, "issuance failed", http.StatusInternalServerError)
			return
		}

		resp := x509SVIDResponse{
			SpiffeID:  svid.SpiffeID,
			Cert:      encodeCertChainPEM(svid.CertChain),
			Key:       encodePKCS8KeyPEM(svid.PrivateKey),
			Bundle:    string(d.TrustBundle.Get()),
			ExpiresAt: svid.ExpiresAt.Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			d.Logger.Error("response encode failed", zap.Error(err))
		}
	}
}

// extractBearerToken reads and validates the Authorization header.
func extractBearerToken(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", errors.New("missing Authorization header")
	}
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", errors.New("invalid Authorization header format")
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", errors.New("empty bearer token")
	}
	return token, nil
}

// encodeCertChainPEM concatenates the DER-encoded chain into a multi-block
// PEM bundle, leaf first. Matches what `cat svid.pem chain.pem` would produce
// from a SPIRE-Agent-served SVID.
func encodeCertChainPEM(chain [][]byte) string {
	var out []byte
	for _, der := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}
	return string(out)
}

// encodePKCS8KeyPEM wraps the PKCS#8 DER-encoded private key the agent
// returns into a PEM block. We do not type-assert on the key algorithm — the
// agent owns key generation and PKCS#8 covers ECDSA, RSA, and Ed25519.
func encodePKCS8KeyPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

// debugSelectors flattens selectors into "type:value" strings for log output.
// Helps diagnose selector-mismatch issues without dumping raw proto.
func debugSelectors(selectors []*types.Selector) []string {
	out := make([]string, 0, len(selectors))
	for _, s := range selectors {
		out = append(out, s.Type+":"+s.Value)
	}
	return out
}

// mock-k8s-api is a local development tool that simulates the K8s API server's
// TokenReview endpoint. It:
//   - generates a CA + server TLS cert pair on startup
//   - generates a placeholder client cert/key (the mock does not actually verify
//     the client, but spire-identity-exchange's TokenReview client config
//     requires CertFile/KeyFile to be set)
//   - mints a JWT-shaped service-account token matching a configurable
//     sub/namespace/serviceAccount, and writes it to a file
//   - serves https on a configurable port
//   - implements POST /apis/authentication.k8s.io/v1/tokenreviews returning a
//     happy-path TokenReviewStatus when the submitted token matches the one
//     this mock issued, and a not-authenticated response otherwise
//
// This mock is intentionally minimal: a single token, one configurable
// audience, no rotation, no real client-cert validation. It exists so the
// integration test in tests/integration/k8s can drive spire-identity-exchange
// end-to-end without requiring kube-apiserver or envtest in CI.
//
// Usage:
//
//	go run ./examples/mock-k8s-api [flags]
//
// Then configure spire-identity-exchange with:
//
//	"k8sSAToken": {
//	  "apiHost": "https://localhost:9998",
//	  "audiences": ["spire-identity-exchange"],
//	  "tls": { "caFile": "...", "certFile": "...", "keyFile": "..." }
//	}
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const tokenReviewPath = "/apis/authentication.k8s.io/v1/tokenreviews"

func main() {
	port := flag.Int("port", 9998, "Port to serve TokenReview on (TLS)")
	audience := flag.String("audience", "spire-identity-exchange", "Token audience and accepted TokenReview Spec.Audience")
	namespace := flag.String("namespace", "default", "kubernetes.io.namespace claim")
	serviceAccount := flag.String("service-account", "test-sa", "kubernetes.io.serviceaccount.name claim")
	issuer := flag.String("issuer", "https://kubernetes.default.svc.cluster.local", "Token issuer (iss claim)")
	ttl := flag.Duration("ttl", 10*time.Minute, "Token lifetime")
	dir := flag.String("dir", ".", "Directory to write ca.pem, client.pem, client.key, server.pem, server.key, and token")
	tokenFile := flag.String("token-file", "token", "Filename (under -dir) to write the SA token to")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("failed to create -dir %q: %v", *dir, err)
	}

	// CA + server cert: the validator needs CAFile to verify the mock's serving
	// cert, so we self-sign a CA, then issue a server cert from it.
	caCert, caKey, caPEM, err := newCA("mock-k8s-api-ca")
	if err != nil {
		log.Fatalf("failed to create CA: %v", err)
	}
	serverPEM, serverKeyPEM, err := newServerCert(caCert, caKey)
	if err != nil {
		log.Fatalf("failed to issue server cert: %v", err)
	}

	// Placeholder client cert: the mock does not verify mTLS, but the validator's
	// client config requires CertFile + KeyFile to be set, so we hand it a
	// self-signed throwaway pair.
	clientPEM, clientKeyPEM, err := newSelfSignedClientCert("mock-k8s-api-client")
	if err != nil {
		log.Fatalf("failed to issue placeholder client cert: %v", err)
	}

	paths := map[string][]byte{
		"ca.pem":     caPEM,
		"server.pem": serverPEM,
		"server.key": serverKeyPEM,
		"client.pem": clientPEM,
		"client.key": clientKeyPEM,
	}
	for name, data := range paths {
		if err := os.WriteFile(filepath.Join(*dir, name), data, 0o600); err != nil {
			log.Fatalf("failed to write %s: %v", name, err)
		}
	}

	// Sign the SA-shaped token with an arbitrary RSA key. The validator does
	// not verify signatures (it parses unverified and trusts TokenReview), but
	// signing keeps the token structurally identical to a real projected SA token.
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate signing key: %v", err)
	}

	sub := fmt.Sprintf("system:serviceaccount:%s:%s", *namespace, *serviceAccount)
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": *issuer,
		"sub": sub,
		"aud": jwt.ClaimStrings{*audience},
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(*ttl).Unix(),
		"jti": uuid.New().String(),
		"kubernetes.io": map[string]interface{}{
			"namespace": *namespace,
			"serviceaccount": map[string]interface{}{
				"name": *serviceAccount,
				"uid":  uuid.New().String(),
			},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "mock-k8s-key-1"
	signed, err := token.SignedString(signingKey)
	if err != nil {
		log.Fatalf("failed to sign SA token: %v", err)
	}

	if err := os.WriteFile(filepath.Join(*dir, *tokenFile), []byte(signed), 0o600); err != nil {
		log.Fatalf("failed to write token: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(tokenReviewPath, tokenReviewHandler(signed, sub, *audience))

	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	fmt.Println("=== Mock K8s API server ===")
	fmt.Printf("apiHost:           https://localhost:%d\n", *port)
	fmt.Printf("Audience:          %s\n", *audience)
	fmt.Printf("SA token sub:      %s\n", sub)
	fmt.Printf("Token expiry:      %s\n", now.Add(*ttl).Format(time.RFC3339))
	fmt.Printf("Materials in:      %s\n", *dir)
	fmt.Printf("TokenReview path:  POST %s\n", tokenReviewPath)
	fmt.Println()
	fmt.Println("Configure spire-identity-exchange with:")
	fmt.Printf(`  "k8sSAToken": {`+"\n")
	fmt.Printf(`    "apiHost":   "https://localhost:%d",`+"\n", *port)
	fmt.Printf(`    "audiences": ["%s"],`+"\n", *audience)
	fmt.Printf(`    "tls": {`+"\n")
	fmt.Printf(`      "caFile":   "%s/ca.pem",`+"\n", *dir)
	fmt.Printf(`      "certFile": "%s/client.pem",`+"\n", *dir)
	fmt.Printf(`      "keyFile":  "%s/client.key"`+"\n", *dir)
	fmt.Printf(`    }`+"\n")
	fmt.Printf(`  }`+"\n")
	fmt.Println()

	if err := server.ListenAndServeTLS(filepath.Join(*dir, "server.pem"), filepath.Join(*dir, "server.key")); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// tokenReviewHandler returns a happy-path TokenReview response when the
// submitted token matches the one this mock issued; otherwise it returns a
// not-authenticated response. The handler echoes the requested audiences back
// in Status.Audiences when they intersect with the configured audience, so
// spire-identity-exchange's audience-binding check passes.
func tokenReviewHandler(expectedToken, username, configuredAudience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "parse body: "+err.Error(), http.StatusBadRequest)
			return
		}

		resp := map[string]interface{}{
			"kind":       "TokenReview",
			"apiVersion": "authentication.k8s.io/v1",
			"status": map[string]interface{}{
				"authenticated": false,
			},
		}

		if req.Spec.Token == expectedToken && intersect(req.Spec.Audiences, configuredAudience) {
			resp["status"] = map[string]interface{}{
				"authenticated": true,
				"audiences":     []string{configuredAudience},
				"user": map[string]interface{}{
					"username": username,
					"groups": []string{
						"system:serviceaccounts",
						"system:serviceaccounts:" + namespaceFromSub(username),
						"system:authenticated",
					},
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// intersect returns true when the empty allowlist case (no audience binding)
// or when audiences contains configuredAudience.
func intersect(audiences []string, configuredAudience string) bool {
	if len(audiences) == 0 {
		return true
	}
	for _, a := range audiences {
		if a == configuredAudience {
			return true
		}
	}
	return false
}

// namespaceFromSub extracts the namespace from a "system:serviceaccount:ns:sa" sub.
func namespaceFromSub(sub string) string {
	const prefix = "system:serviceaccount:"
	if len(sub) <= len(prefix) {
		return ""
	}
	rest := sub[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			return rest[:i]
		}
	}
	return rest
}

// newCA generates a self-signed CA cert + key and returns the cert in both
// parsed and PEM forms (PEM for writing to disk, parsed for issuing leaf certs).
func newCA(commonName string) (*x509.Certificate, *rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// newServerCert issues a server cert signed by the given CA, valid for
// localhost / 127.0.0.1 (sufficient for the integration test's single-host CI runner).
func newServerCert(caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mock-k8s-api"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

// newSelfSignedClientCert generates a self-signed cert + key. The mock does
// not verify client certs, but spire-identity-exchange's TokenReview config
// requires CertFile/KeyFile to be set.
func newSelfSignedClientCert(commonName string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

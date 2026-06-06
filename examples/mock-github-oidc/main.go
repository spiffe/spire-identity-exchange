// mock-github-oidc is a local development tool that:
//   - generates an RSA key pair on startup
//   - serves the public key as a JWKS endpoint at http://localhost:<port>/.well-known/jwks
//   - signs and prints a JWT with configurable GitHub OIDC-like claims
//
// Usage:
//
//	go run ./examples/mock-github-oidc [flags]
//
// Then configure spire-identity-exchange with:
//
//	"githubOIDC": {
//	  "issuer":  "http://localhost:9999",
//	  "jwksUri": "http://localhost:9999/.well-known/jwks",
//	  ...
//	}
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func main() {
	port := flag.Int("port", 9999, "Port to serve JWKS on")
	issuer := flag.String("issuer", "", "Token issuer (defaults to http://localhost:<port>)")
	audience := flag.String("audience", "spire-identity-exchange", "Token audience")
	repository := flag.String("repository", "my-org/my-repo", "repository claim")
	enterprise := flag.String("enterprise", "my-enterprise", "enterprise claim")
	actor := flag.String("actor", "test-actor", "actor claim")
	ref := flag.String("ref", "refs/heads/main", "ref claim")
	eventName := flag.String("event-name", "push", "event_name claim")
	ttl := flag.Duration("ttl", 10*time.Minute, "Token lifetime")
	tokenFile := flag.String("token", "", "Filename to write the token to")
	flag.Parse()

	if *issuer == "" {
		*issuer = fmt.Sprintf("http://localhost:%d", *port)
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate RSA key: %v", err)
	}

	kid := "mock-key-1"
	workflowFile := "mock-workflow.yml"
	workflowRef := fmt.Sprintf("%s/.github/workflows/%s@%s", *repository, workflowFile, *ref)

	// Build JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		// Standard claims
		"iss": *issuer,
		"aud": jwt.ClaimStrings{*audience},
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(*ttl).Unix(),
		"jti": uuid.New().String(),
		// GitHub OIDC claims
		"repository":          *repository,
		"repository_owner":    firstSegment(*repository),
		"sha":                 "aabbccdd00112233445566778899aabbccdd0011",
		"ref":                 *ref,
		"workflow_ref":        workflowRef,
		"job_workflow_ref":    workflowRef,
		"actor":               *actor,
		"runner_environment":  "github-hosted",
		"run_id":              "123456789",
		"run_attempt":         "1",
		"event_name":          *eventName,
		"enterprise":          *enterprise,
		"workflow":            workflowFile,
		"head_ref":            "",
		"base_ref":            "",
		"ref_type":            "branch",
		"repository_visibility": "private",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("failed to sign token: %v", err)
	}

	// Build JWKS from public key
	jwk := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}

	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		log.Fatalf("failed to marshal JWKS: %v", err)
	}

openIDConfiguration := fmt.Sprintf("{\"issuer\":\"%s\",\"jwks_uri\":\"%s/.well-known/jwks\",\"subject_types_supported\":[\"public\"],\"response_types_supported\":[\"code\"],\"claims_supported\":[\"sub\",\"aud\",\"exp\",\"nbf\",\"iat\",\"iss\",\"act\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"scopes_supported\":[\"openid\"],\"response_modes_supported\":[\"query\"]}", *issuer, *issuer)

	// Print usage
	fmt.Println("=== Mock GitHub OIDC Server ===")
	fmt.Printf("OpenID Configuration: http://localhost:%d/.well-known/openid-configuration\n", *port)
	fmt.Printf("JWKS endpoint: http://localhost:%d/.well-known/jwks\n", *port)
	fmt.Printf("Issuer:        %s\n", *issuer)
	fmt.Printf("Audience:      %s\n", *audience)
	fmt.Printf("Token expiry:  %s\n", now.Add(*ttl).Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Configure spire-identity-exchange with:")
	fmt.Printf(`  "githubOIDC": {`+"\n")
	fmt.Printf(`    "issuer":  "%s",`+"\n", *issuer)
	fmt.Printf(`    "jwksUri": "http://localhost:%d/.well-known/jwks"`+"\n", *port)
	fmt.Printf(`  }`+"\n")
	fmt.Println()
	fmt.Println("=== Copy-paste this to set your token ===")
	fmt.Println()
	fmt.Printf("export GITHUB_TOKEN=\"%s\"\n", signed)
	fmt.Println()
	fmt.Println("=== Example grpcurl call ===")
	fmt.Println()
	fmt.Printf("grpcurl -insecure \\\n")
	fmt.Printf("  -d '{\"githubOIDC\":{\"githubToken\":\"%s\"},\"serverKeyGenRequest\":{}}' \\\n", signed)
	fmt.Printf("  localhost:8443 \\\n")
	fmt.Printf("  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate\n")
	fmt.Println()
	fmt.Println("=== Example curl call (HTTP gateway) ===")
	fmt.Println()
	fmt.Printf("curl -k -X POST https://localhost:8444/v1/mint-certificate \\\n")
	fmt.Printf("  -H 'Content-Type: application/json' \\\n")
	fmt.Printf("  -d '{\"githubOIDC\":{\"githubToken\":\"%s\"},\"serverKeyGenRequest\":{}}'\n", signed)
	fmt.Println()
	fmt.Printf("Serving JWKS at http://localhost:%d/.well-known/jwks ...\n", *port)

	if *tokenFile != "" {
		if err := os.WriteFile(*tokenFile, []byte(signed), 0600); err != nil {
			log.Fatalf("failed to write token to %q: %v", *tokenFile, err)
		}
	}

	// Serve JWKS
	http.HandleFunc("/.well-known/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	})

	// Serve openid-configuration
	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openIDConfiguration))
	})


	if err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil); err != nil {
		log.Fatalf("failed to start JWKS server: %v", err)
	}
}

func firstSegment(s string) string {
	for i, c := range s {
		if c == '/' {
			return s[:i]
		}
	}
	return s
}

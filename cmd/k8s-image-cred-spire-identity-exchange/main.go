package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubelet/pkg/apis/credentialprovider/v1"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

type jwtSVIDRequest struct {
	Audiences []string `json:"audiences"`
}

type jwtSVIDResponse struct {
	SpiffeID  string `json:"spiffeId"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"` // Unix seconds
}

func main() {
	usernameFlag := flag.String("username", "", "Registry username (Required)")
	modeFlag := flag.String("mode", "spire-identity-exchange", "Operation mode: spire-identity-exchange, passthrough-k8s, or passthrough-spiffe")
	urlFlag := flag.String("url", "", "URL (Required if mode is spire-identity-exchange)")
	stackFlag := flag.String("stack", "", "Stack (Required if SPIFFE workload API is enabled)")
	registryAudienceFlag := flag.String("registry-audience", "", "Registry audience (Required if SPIFFE workload API is enabled")
	spiffeAudienceFlag := flag.String("spiffe-audience", "", "SPIFFE audience (Required if SPIFFE workload API is enabled)")
	disableSpiffeFlag := flag.Bool("disable-spiffe-workload-api", false, "Disable SPIFFE workload API")
	timeoutFlag := flag.Duration("timeout", 0, "Global timeout for the entire process (e.g., 5s, 30s). 0 means no timeout.")
	spiffeIDFlag := flag.String("spiffe-id", "", "SPIFFE ID to validate against the identity exchange.")
	k8sPSATFlag := flag.String("k8s-psat", "k8s_psat", "Name of the k8s psat plugin in the stack")
	spiffeFlag := flag.String("spiffe", "spiffe", "Name of the spiffe plugin in the stack")
	caFileFlag := flag.String("ca-file", "", "Path to a custom CA file to validate the URL's TLS certificate")

	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *timeoutFlag > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, *timeoutFlag)
		defer timeoutCancel()

		go func() {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				fmt.Fprintf(os.Stderr, "error: process timed out after %v\n", *timeoutFlag)
				os.Exit(1)
			}
		}()
	}

	if *usernameFlag == "" {
		fmt.Fprintf(os.Stderr, "error: --username flag is required\n")
		os.Exit(1)
	}

	if *modeFlag == "passthrough-k8s" {
		*disableSpiffeFlag = true
	}

	if *modeFlag == "passthrough-spiffe" && *disableSpiffeFlag {
		fmt.Fprintf(os.Stderr, "error: cannot disable the SPIFFE workload API when using mode passthrough-spiffe\n")
		os.Exit(1)
	}

	if *modeFlag == "spire-identity-exchange" {
		if *registryAudienceFlag == "" {
			fmt.Fprintf(os.Stderr, "error: --registry-audience flag is required when mode is spire-identity-exchange\n")
			os.Exit(1)
		}
		if *urlFlag == "" {
			fmt.Fprintf(os.Stderr, "error: --url flag is required when mode is spire-identity-exchange\n")
			os.Exit(1)
		}
		if *stackFlag == "" {
			fmt.Fprintf(os.Stderr, "error: --stack flag is required when mode is spire-identity-exchange\n")
			os.Exit(1)
		}
	}

	if !*disableSpiffeFlag && *spiffeAudienceFlag == "" {
		fmt.Fprintf(os.Stderr, "error: --spiffe-audience flag is required unless --disable-spiffe-workload-api is set\n")
		os.Exit(1)
	}

	var spiffeToken string
	if !*disableSpiffeFlag {
		var err error
		spiffeToken, err = fetchSpiffeJWT(ctx, *spiffeAudienceFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch SPIFFE JWT token: %v\n", err)
			os.Exit(1)
		}
	}

	var request v1.CredentialProviderRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode request from stdin: %v\n", err)
		os.Exit(1)
	}

	saToken := request.ServiceAccountToken
	switch *modeFlag {
	case "passthrough-k8s", "spire-identity-exchange":
		if saToken == "" {
			fmt.Fprintf(os.Stderr, "error: service account token is required for mode %q\n", *modeFlag)
			os.Exit(1)
		}
	case "passthrough-spiffe":
	}

	var token string
	switch *modeFlag {
	case "passthrough-k8s":
		token = saToken
	case "passthrough-spiffe":
		token = spiffeToken
	default:
		var err error
		token, err = exchangeTokenForRegistryCreds(*urlFlag, *stackFlag, saToken, spiffeToken, *registryAudienceFlag, *k8sPSATFlag, *spiffeFlag, *spiffeIDFlag, *caFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to exchange token for registry credentials: %v\n", err)
			os.Exit(1)
		}
	}

	username := *usernameFlag

	remaining, err := getRemainingCacheDuration(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get remaining duration on the token: %v\n", err)
		os.Exit(1)
	}

	response := v1.CredentialProviderResponse{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "credentialprovider.kubelet.k8s.io/v1",
			Kind:       "CredentialProviderResponse",
		},
		CacheKeyType:  v1.RegistryPluginCacheKeyType,
		CacheDuration: remaining,
		Auth: map[string]v1.AuthConfig{
			request.Image: {
				Username: username,
				Password: token,
			},
		},
	}

	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode response to stdout: %v\n", err)
		os.Exit(1)
	}
}

func fetchSpiffeJWT(ctx context.Context, audience string) (string, error) {
	token, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		return "", fmt.Errorf("could not fetch SPIFFE JWT token from workload API: %w", err)
	}
	return token.Marshal(), nil
}

func getRemainingCacheDuration(jwtToken string) (*metav1.Duration, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	payloadSegment := parts[1]

	if l := len(payloadSegment) % 4; l > 0 {
		payloadSegment += strings.Repeat("=", 4-l)
	}

	payloadBytes, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token claims: %w", err)
	}

	if claims.Exp == 0 {
		return nil, fmt.Errorf("token payload is missing an 'exp' claim")
	}

	expTime := time.Unix(claims.Exp, 0)
	remaining := time.Until(expTime)

	if remaining <= 0 {
		return &metav1.Duration{Duration: 0}, nil
	}

	if remaining > 30*time.Second {
		remaining -= 30 * time.Second
	}

	return &metav1.Duration{Duration: remaining}, nil
}

func exchangeTokenForRegistryCreds(baseURL, stack, saToken, spiffeToken, registryAudience, k8sPSATFlag, spiffeFlag, expectedSpiffeID, caFile string) (string, error) {
	if saToken == "" {
		return "", fmt.Errorf("empty service account token")
	}

	bearerToken := saToken
	if spiffeToken != "" {
		bearerToken = fmt.Sprintf("%s=%s:%s=%s", k8sPSATFlag, saToken, spiffeFlag, spiffeToken)
	}

	url := fmt.Sprintf("%s/api/v1/svid/%s/jwt", strings.TrimSuffix(baseURL, "/"), stack)

	reqBody := jwtSVIDRequest{
		Audiences: []string{registryAudience},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")

	var client *http.Client

	if expectedSpiffeID != "" {
		ctx := context.Background()
		source, err := workloadapi.NewBundleSource(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to create BundleSource: %w", err)
		}
		defer source.Close()

		id, err := spiffeid.FromString(expectedSpiffeID)
		if err != nil {
			return "", fmt.Errorf("invalid spiffe-id: %w", err)
		}

		tlsConfig := tlsconfig.TLSClientConfig(source, tlsconfig.AuthorizeID(id))
		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	} else if caFile != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}

		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return "", fmt.Errorf("failed to read CA file %q: %w", caFile, err)
		}

		if ok := rootCAs.AppendCertsFromPEM(caBytes); !ok {
			return "", fmt.Errorf("failed to parse any certificates from CA file %q", caFile)
		}

		client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: rootCAs,
				},
			},
		}
	} else {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned non-200 status: %d", resp.StatusCode)
	}

	var result jwtSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Token, nil
}


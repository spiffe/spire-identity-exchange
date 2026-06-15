package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	socket       string
	bundleSource *workloadapi.BundleSource
	targetDomain spiffeid.TrustDomain
)

func trustBundleHandler(w http.ResponseWriter, r *http.Request) {
	bundle, err := bundleSource.GetBundleForTrustDomain(targetDomain)
	if err != nil {
		fmt.Printf("Failed to locate bundle for trust domain %s: %v\n", targetDomain.String(), err)
		http.Error(w, "Trust bundle not found for configured domain", http.StatusNotFound)
		return
	}

	certs := bundle.X509Authorities()
	if len(certs) == 0 {
		fmt.Printf("No X509 authorities found in the bundle for %s\n", targetDomain.String())
		http.Error(w, "No certificates in trust bundle", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)

	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		if err := pem.Encode(w, pemBlock); err != nil {
			fmt.Printf("Failed to write PEM block to response: %v\n", err)
			return
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "<socket_path_to_listen_on>")
		return
	}
	socket = os.Args[1]

	envTD := os.Getenv("SPIFFE_TRUST_DOMAIN")
	if envTD == "" {
		fmt.Fprintln(os.Stderr, "Error: SPIFFE_TRUST_DOMAIN environment variable is missing or empty")
		os.Exit(1)
	}

	var err error
	targetDomain, err = spiffeid.TrustDomainFromString(envTD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to parse trust domain from SPIFFE_TRUST_DOMAIN: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Configured to serve trust bundle for: %s\n", targetDomain.String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println("Connecting to SPIFFE Workload API and initializing background stream...")

	bundleSource, err = workloadapi.NewBundleSource(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to initialize SPIFFE bundle source: %v\n", err)
		os.Exit(1)
	}
	defer bundleSource.Close()

	fmt.Printf("Starting HTTP server on Unix Socket: %s\n", socket)

	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Failed to clean socket path: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/trustbundle", trustBundleHandler)

	server := http.Server{
		Handler: mux,
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on unix socket: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	_ = os.Chmod(socket, 0777)

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Server encountered error: %v\n", err)
		os.Exit(1)
	}
}

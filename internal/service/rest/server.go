package rest

import "net/http"

// NewMux builds a *http.ServeMux with the REST routes wired up using the
// supplied dependencies. Keeps route registration in one place so the
// lifecycle code in runner.go can simply build it and pass it to the listener.
func NewMux(d Deps) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/trustbundle/x509", HandleTrustBundleX509(d))
	mux.HandleFunc("POST /api/v1/svid/{plugin}/x509", HandleGetX509SVID(d))
	return mux
}

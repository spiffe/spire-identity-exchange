// Package rest implements the HTTP/REST surface of spire-identity-exchange.
// It is kept separate from the gRPC handler package so that runner.go can stay
// focused on server lifecycle.
package rest

import (
	"encoding/pem"
	"sync"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.uber.org/zap"
)

// TrustBundleCache is a goroutine-safe in-memory mirror of the local trust
// bundle delivered by the SPIRE Agent's Workload API. It implements
// workloadapi.X509ContextWatcher so it can be passed directly into
// workloadapi.Client.WatchX509Context.
//
// Encoding is done eagerly on each update so the HTTP hot path is a single
// RLock + slice copy. SVID-only updates from the agent (no bundle change) do
// a wasteful re-encode of the same PEM but keep the cache code branch-free.
type TrustBundleCache struct {
	mu       sync.RWMutex
	pemBytes []byte
	logger   *zap.Logger
}

// NewTrustBundleCache creates an empty cache. Pass the returned value to
// workloadapi.Client.WatchX509Context to start populating it.
func NewTrustBundleCache(logger *zap.Logger) *TrustBundleCache {
	return &TrustBundleCache{logger: logger}
}

// Get returns a defensive copy of the cached PEM bytes.
// Returns nil if no update has been received yet.
func (c *TrustBundleCache) Get() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.pemBytes) == 0 {
		return nil
	}
	return append([]byte(nil), c.pemBytes...)
}

// OnX509ContextUpdate implements workloadapi.X509ContextWatcher. Called by
// go-spiffe whenever the agent pushes a new X.509 context — on initial
// subscribe, on SVID rotation, on bundle/CA change, on entry change, and on
// post-reconnect re-subscribe.
func (c *TrustBundleCache) OnX509ContextUpdate(x509Ctx *workloadapi.X509Context) {
	if x509Ctx == nil || x509Ctx.Bundles == nil {
		return
	}

	var localPemBytes []byte
	for _, bundle := range x509Ctx.Bundles.Bundles() {
		for _, cert := range bundle.X509Authorities() {
			b := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			localPemBytes = append(localPemBytes, b...)
		}
	}

	c.mu.Lock()
	c.pemBytes = localPemBytes
	c.mu.Unlock()
}

// OnX509ContextWatchError implements workloadapi.X509ContextWatcher. Logged at
// info level — go-spiffe handles reconnect internally, so these are
// transient. An operator alarming on sustained errors should look at the
// process logs.
func (c *TrustBundleCache) OnX509ContextWatchError(err error) {
	if c.logger != nil {
		c.logger.Info("workload API watcher transient error", zap.Error(err))
	}
}

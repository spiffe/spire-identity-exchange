package cache

import (
	"context"
	"sync"
	"time"
)

// ReplayCache tracks seen token IDs to detect replay attacks.
type ReplayCache interface {
	// Contains returns true if the token ID has already been recorded.
	// This is a read-only check used for early replay rejection before
	// expensive token verification.
	Contains(jti string) bool
	// Add records a token ID as seen. Returns false if already present (replay detected).
	Add(jti string, expiry time.Time) bool
}

type inMemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewInMemoryReplayCache returns an in-memory ReplayCache that automatically
// evicts expired entries. It is safe for concurrent use but does not survive
// process restarts or share state across instances.
// The eviction goroutine runs until ctx is cancelled.
func NewInMemoryReplayCache(ctx context.Context) ReplayCache {
	c := &inMemoryReplayCache{
		entries: make(map[string]time.Time),
	}
	go c.evict(ctx)
	return c
}

func (c *inMemoryReplayCache) Contains(jti string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, seen := c.entries[jti]
	return seen
}

func (c *inMemoryReplayCache) Add(jti string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.entries[jti]; seen {
		return false
	}
	c.entries[jti] = expiry
	return true
}

func (c *inMemoryReplayCache) evict(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			c.mu.Lock()
			for jti, expiry := range c.entries {
				if now.After(expiry) {
					delete(c.entries, jti)
				}
			}
			c.mu.Unlock()
		}
	}
}

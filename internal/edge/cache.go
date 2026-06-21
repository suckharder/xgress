// Package edge is xgress's native server-side HTTP cache. The Souin Traefik plugin
// can't use Redis through the catalog plugin model (v1.7 split storages out and
// no Redis storage ships as a Traefik plugin), so to deliver a real shared cache
// across nodes xgress caches itself: cache-enabled hosts route to this loopback
// edge, which caches GET responses and reverse-proxies misses to the backend.
// Storage is in-memory by default, or Redis (XGRESS_REDIS_URL) for a shared cache.
package edge

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheStore is the cache backend.
type CacheStore interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration)
	Name() string
}

// memStore is a simple in-process TTL cache.
type memStore struct {
	mu    sync.RWMutex
	items map[string]memItem
}

type memItem struct {
	val []byte
	exp time.Time
}

// NewMemStore returns an in-memory cache with periodic expiry sweeping.
func NewMemStore() *memStore {
	m := &memStore{items: map[string]memItem{}}
	go func() {
		t := time.NewTicker(time.Minute)
		for range t.C {
			now := time.Now()
			m.mu.Lock()
			for k, it := range m.items {
				if now.After(it.exp) {
					delete(m.items, k)
				}
			}
			m.mu.Unlock()
		}
	}()
	return m
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.RLock()
	it, ok := m.items[key]
	m.mu.RUnlock()
	if !ok || time.Now().After(it.exp) {
		return nil, false
	}
	return it.val, true
}

func (m *memStore) Set(_ context.Context, key string, val []byte, ttl time.Duration) {
	m.mu.Lock()
	m.items[key] = memItem{val: val, exp: time.Now().Add(ttl)}
	m.mu.Unlock()
}

func (m *memStore) Name() string { return "in-memory" }

// redisStore is a shared cache backed by Redis.
type redisStore struct {
	c      *redis.Client
	prefix string
}

// NewRedisStore parses a redis URL (redis://host:port/db or host:port) and
// returns a Redis-backed cache.
func NewRedisStore(url string) (*redisStore, error) {
	opt, err := redis.ParseURL(normalizeRedisURL(url))
	if err != nil {
		return nil, err
	}
	return &redisStore{c: redis.NewClient(opt), prefix: "xgresscache:"}, nil
}

func normalizeRedisURL(u string) string {
	if len(u) >= 8 && (u[:8] == "redis://") {
		return u
	}
	if len(u) >= 9 && u[:9] == "rediss://" {
		return u
	}
	return "redis://" + u
}

func (r *redisStore) Get(ctx context.Context, key string) ([]byte, bool) {
	b, err := r.c.Get(ctx, r.prefix+key).Bytes()
	if err != nil {
		return nil, false
	}
	return b, true
}

func (r *redisStore) Set(ctx context.Context, key string, val []byte, ttl time.Duration) {
	_ = r.c.Set(ctx, r.prefix+key, val, ttl).Err()
}

func (r *redisStore) Name() string { return "redis" }

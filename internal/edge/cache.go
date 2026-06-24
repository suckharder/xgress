// Package edge is xgress's native server-side HTTP cache. The Souin Traefik plugin
// can't use Redis through the catalog plugin model (v1.7 split storages out and
// no Redis storage ships as a Traefik plugin), so to deliver a real shared cache
// across nodes xgress caches itself: cache-enabled hosts route to this loopback
// edge, which caches GET responses and reverse-proxies misses to the backend.
// Storage is in-memory by default, or Redis (XGRESS_REDIS_URL) for a shared cache.
package edge

import (
	"container/list"
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

// Default bounds for the in-memory cache (overridable via MemLimits / config).
const (
	defaultCacheMaxBytes      int64 = 128 << 20 // 128 MiB total budget
	defaultCacheMaxEntryBytes int64 = 8 << 20   // 8 MiB per cached entry
	defaultCacheMaxEntries          = 50_000    // caps map/list overhead under tiny-entry floods
)

// MemLimits bounds the in-memory cache. Zero fields fall back to the defaults.
type MemLimits struct {
	MaxBytes      int64 // total byte budget across all entries
	MaxEntryBytes int64 // per-entry ceiling (larger values are not cached)
	MaxEntries    int   // hard cap on entry count
}

// memStore is a bounded in-process LRU+TTL cache. It enforces a total byte
// budget, a per-entry ceiling, and an entry-count cap with least-recently-used
// eviction, so a flood of distinct cacheable URLs can never grow it without
// bound (the cache key includes the full RequestURI). The Redis backend is
// externally bounded, so this applies to the in-memory store only.
type memStore struct {
	mu            sync.Mutex
	ll            *list.List               // front = most-recently used
	items         map[string]*list.Element // key -> *list.Element holding *memEntry
	curBytes      int64
	maxBytes      int64
	maxEntryBytes int64
	maxEntries    int
}

type memEntry struct {
	key  string
	val  []byte
	exp  time.Time
	size int64 // len(key)+len(val), tracked so eviction accounting can't drift
}

// NewMemStore returns a bounded in-memory cache with periodic expiry sweeping.
// The sweep goroutine exits when ctx is cancelled, so it never leaks past
// shutdown (it is wired to the app context in cmd/xgress/main.go).
func NewMemStore(ctx context.Context, lim MemLimits) *memStore {
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = defaultCacheMaxBytes
	}
	if lim.MaxEntryBytes <= 0 {
		lim.MaxEntryBytes = defaultCacheMaxEntryBytes
	}
	if lim.MaxEntries <= 0 {
		lim.MaxEntries = defaultCacheMaxEntries
	}
	m := &memStore{
		ll:            list.New(),
		items:         map[string]*list.Element{},
		maxBytes:      lim.MaxBytes,
		maxEntryBytes: lim.MaxEntryBytes,
		maxEntries:    lim.MaxEntries,
	}
	go m.sweepLoop(ctx)
	return m
}

func (m *memStore) sweepLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sweepExpired()
		}
	}
}

func (m *memStore) sweepExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, el := range m.items {
		if now.After(el.Value.(*memEntry).exp) {
			m.removeLocked(el)
		}
	}
}

func (m *memStore) Get(_ context.Context, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	el, ok := m.items[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*memEntry)
	if time.Now().After(e.exp) {
		m.removeLocked(el)
		return nil, false
	}
	m.ll.MoveToFront(el)
	return e.val, true
}

func (m *memStore) Set(_ context.Context, key string, val []byte, ttl time.Duration) {
	if int64(len(val)) > m.maxEntryBytes {
		return // too large to cache; bounded buffering makes this rare
	}
	size := int64(len(key) + len(val))
	exp := time.Now().Add(ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.items[key]; ok {
		e := el.Value.(*memEntry)
		m.curBytes += size - e.size
		e.val, e.exp, e.size = val, exp, size
		m.ll.MoveToFront(el)
	} else {
		el := m.ll.PushFront(&memEntry{key: key, val: val, exp: exp, size: size})
		m.items[key] = el
		m.curBytes += size
	}
	for (m.curBytes > m.maxBytes || m.ll.Len() > m.maxEntries) && m.ll.Len() > 0 {
		m.removeLocked(m.ll.Back())
	}
}

// removeLocked drops an element from the list, the index, and the byte budget.
// The caller must hold m.mu.
func (m *memStore) removeLocked(el *list.Element) {
	e := el.Value.(*memEntry)
	m.ll.Remove(el)
	delete(m.items, e.key)
	m.curBytes -= e.size
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

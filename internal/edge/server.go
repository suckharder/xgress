package edge

import (
	"bytes"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// Server is the cache/proxy edge for cache-enabled hosts.
type Server struct {
	cache      CacheStore
	defaultTTL time.Duration
	token      string // required X-xgress-Cache-Token (empty = ungated, loopback-only)
	log        *slog.Logger
	client     *http.Client

	mu      sync.RWMutex
	byHost  map[string]*store.Host // domain -> host
	rrState sync.Map               // hostID -> *uint64 round-robin counter
}

// New builds an edge server with the given cache store, default TTL, and auth token.
// A non-empty token is required on every request (injected by the renderer on
// cache-routed hosts), so the edge is safe to expose on the Docker network; empty
// leaves it ungated (loopback-only single-container behavior).
func New(cache CacheStore, defaultTTL time.Duration, token string, log *slog.Logger) *Server {
	if defaultTTL <= 0 {
		defaultTTL = 2 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cache: cache, defaultTTL: defaultTTL, token: token, log: log,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		byHost: map[string]*store.Host{},
	}
}

// CacheName reports the cache storage backend name.
func (s *Server) CacheName() string { return s.cache.Name() }

// SetHosts updates the domain→host index (called by the engine on every reload).
func (s *Server) SetHosts(hosts []*store.Host) {
	idx := map[string]*store.Host{}
	for _, h := range hosts {
		if h.Kind != store.HostKindProxy || !h.Enabled {
			continue
		}
		for _, d := range h.Domains {
			idx[strings.ToLower(d)] = h
		}
	}
	s.mu.Lock()
	s.byHost = idx
	s.mu.Unlock()
}

func (s *Server) host(domain string) *store.Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byHost[strings.ToLower(domain)]
}

// ServeHTTP caches GETs and reverse-proxies everything to the host's backend.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Token gate: the edge proxies all hosts and bypasses Traefik's middleware chain,
	// so when it's network-reachable (external mode) it must reject anything that
	// didn't come through Traefik (which carries the renderer-injected token).
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(config.EdgeTokenHeader)), []byte(s.token)) != 1 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	domain := r.Host
	if i := strings.IndexByte(domain, ':'); i >= 0 {
		domain = domain[:i]
	}
	h := s.host(domain)
	if h == nil {
		// Generic message to the (public) client; detail to the log.
		s.log.Warn("cache edge: no host for request", "host", domain)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	target := s.pickBackend(h, r.URL.Path)
	if target == "" {
		s.log.Warn("cache edge: no backend for host", "host", domain)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	cacheable := requestCacheable(r)
	key := r.Method + " " + domain + " " + r.URL.RequestURI()
	if cacheable {
		if raw, ok := s.cache.Get(r.Context(), key); ok {
			if cr, err := decode(raw); err == nil {
				writeResponse(w, cr, "HIT")
				return
			}
		}
	}

	cr, err := s.proxy(r, target, domain)
	if err != nil {
		// Don't leak the upstream error (internal hostnames/transport detail) to the
		// public client; log it instead.
		s.log.Warn("cache edge: upstream error", "host", domain, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	if cacheable {
		if ttl, ok := responseTTL(cr, s.defaultTTL); ok {
			if raw, err := encode(cr); err == nil {
				s.cache.Set(r.Context(), key, raw, ttl)
			}
		}
	}
	writeResponse(w, cr, "MISS")
}

func (s *Server) pickBackend(h *store.Host, _ string) string {
	ups := h.Upstreams
	if len(ups) == 0 {
		for _, g := range h.BackendGroups {
			if len(g.Upstreams) > 0 {
				ups = g.Upstreams
				break
			}
		}
	}
	if len(ups) == 0 {
		return ""
	}
	ctr, _ := s.rrState.LoadOrStore(h.ID, new(uint64))
	n := atomic.AddUint64(ctr.(*uint64), 1)
	u := ups[int(n)%len(ups)]
	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	if u.Port != 0 {
		return fmt.Sprintf("%s://%s:%d", scheme, u.Host, u.Port)
	}
	return fmt.Sprintf("%s://%s", scheme, u.Host)
}

// cachedResponse is the on-cache representation of an HTTP response.
type cachedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func (s *Server) proxy(r *http.Request, target, domain string) (*cachedResponse, error) {
	outURL := target + r.URL.RequestURI()
	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, body)
	if err != nil {
		return nil, err
	}
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Connection") {
			continue
		}
		out.Header[k] = vv
	}
	out.Host = r.Host                      // preserve the public Host for the backend
	out.Header.Del(config.EdgeTokenHeader) // never leak the edge token to the real backend
	out.Header.Set("X-Forwarded-Host", r.Host)
	out.Header.Set("X-Forwarded-Proto", schemeOf(r))

	resp, err := s.client.Do(out)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	hdr := resp.Header.Clone()
	hdr.Del("Connection")
	return &cachedResponse{Status: resp.StatusCode, Header: hdr, Body: b}, nil
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		return p
	}
	return "http"
}

func writeResponse(w http.ResponseWriter, cr *cachedResponse, status string) {
	for k, vv := range cr.Header {
		w.Header()[k] = vv
	}
	w.Header().Set("X-xgress-Cache", status)
	w.WriteHeader(cr.Status)
	_, _ = w.Write(cr.Body)
}

// requestCacheable reports whether a request is eligible for cache lookup/store.
func requestCacheable(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Authorization") != "" {
		return false
	}
	if cc := r.Header.Get("Cache-Control"); strings.Contains(strings.ToLower(cc), "no-store") {
		return false
	}
	return true
}

// responseTTL decides whether/how long to cache a response (shared-cache rules).
func responseTTL(cr *cachedResponse, def time.Duration) (time.Duration, bool) {
	if cr.Status != http.StatusOK {
		return 0, false
	}
	if len(cr.Header.Values("Set-Cookie")) > 0 {
		return 0, false
	}
	cc := strings.ToLower(cr.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return 0, false
	}
	if v := vary(cr.Header.Get("Vary")); v {
		return 0, false
	}
	if d, ok := maxAge(cc); ok {
		if d <= 0 {
			return 0, false
		}
		return d, true
	}
	return def, true
}

func vary(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && !strings.EqualFold(v, "Accept-Encoding")
}

func maxAge(cc string) (time.Duration, bool) {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		for _, key := range []string{"s-maxage=", "max-age="} {
			if strings.HasPrefix(part, key) {
				if n, err := strconv.Atoi(part[len(key):]); err == nil {
					return time.Duration(n) * time.Second, true
				}
			}
		}
	}
	return 0, false
}

func encode(cr *cachedResponse) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cr); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decode(raw []byte) (*cachedResponse, error) {
	var cr cachedResponse
	if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&cr); err != nil {
		return nil, err
	}
	return &cr, nil
}

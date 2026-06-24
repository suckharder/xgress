package edge

import (
	"bytes"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/secmetrics"
	"github.com/suckharder/xgress/internal/store"
)

// Server is the loopback edge for cache- and/or WAF-enabled hosts. Traefik routes
// such a host's service here (token-gated); the edge runs the native Coraza WAF
// (when h.WAF), serves/stores the cache (when h.Cache), and reverse-proxies to the
// host's real backend — buffered for cacheable GETs, streamed for WebSocket
// upgrades and everything else.
type Server struct {
	cache             CacheStore
	defaultTTL        time.Duration
	token             string // required X-xgress-Cache-Token (empty = ungated, loopback-only)
	log               *slog.Logger
	client            *http.Client
	transport         *http.Transport // shared, pool-tuned; used by client + the stream proxy (P1-6)
	maxEntryBytes     int64           // cap on bytes buffered per request; larger responses stream (P0-4)
	wafRespFailClosed bool            // block (500) on a WAF response-phase processing error (S4)

	waf          wafState // hot-swappable Coraza engine
	wafEnabled   atomic.Bool
	cacheEnabled atomic.Bool
	sec          *secmetrics.Collector // WAF detections feed here (nil = no metrics)

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
	tr := newEdgeTransport()
	s := &Server{
		cache: cache, defaultTTL: defaultTTL, token: token, log: log,
		client:        &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		transport:     tr,
		byHost:        map[string]*store.Host{},
		maxEntryBytes: defaultCacheMaxEntryBytes,
	}
	// Caching defaults on; the engine overrides both flags on every reload via
	// SetEnabled. WAF stays off until an engine is built and enabled.
	s.cacheEnabled.Store(true)
	return s
}

// newEdgeTransport returns a connection-pool-tuned transport shared by the buffered
// client and the streaming reverse proxy. http.DefaultTransport caps
// MaxIdleConnsPerHost at 2, which throttles a busy edge into constant connection
// setup/teardown to each backend; these limits keep hot backends pooled. (P1-6)
func newEdgeTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 256
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	t.ForceAttemptHTTP2 = true
	return t
}

// SetEntryLimit sets the per-request buffer ceiling (bytes). Responses larger than
// this are streamed to the client instead of being held in memory or cached, which
// bounds per-request heap use. A non-positive value keeps the default. Call before
// serving (wired from config in cmd/xgress/main.go).
func (s *Server) SetEntryLimit(n int64) {
	if n > 0 {
		s.maxEntryBytes = n
	}
}

// SetWAFResponseFailClosed controls whether a WAF response-phase processing error
// blocks the response (500) instead of serving it. Default (false) is fail-open; the
// request phase always fails closed. Call before serving (wired from config). (S4)
func (s *Server) SetWAFResponseFailClosed(v bool) { s.wafRespFailClosed = v }

// wafResponseFailMode is the result returned when the WAF response phase hits an
// internal processing error: block (500) when fail-closed is configured, else pass.
func (s *Server) wafResponseFailMode() wafResult {
	if s.wafRespFailClosed {
		return failClosed()
	}
	return pass()
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

// ServeHTTP runs the WAF (when enabled for the host), serves/stores the cache
// (when enabled), and reverse-proxies to the host's backend.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Token gate: the edge proxies all hosts and bypasses Traefik's middleware chain,
	// so when it's network-reachable (external mode) it must reject anything that
	// didn't come through Traefik (which carries the renderer-injected token).
	if s.token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(config.EdgeTokenHeader)), []byte(s.token)) != 1 {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	domain := hostOnly(r.Host)
	h := s.host(domain)
	if h == nil {
		// Generic message to the (public) client; detail to the log.
		s.log.Warn("edge: no host for request", "host", domain)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	applyWAF := h.WAF && s.wafActive()
	applyCache := h.Cache && s.cacheEnabled.Load()

	// WAF request phase (before cache lookup, so an attack is blocked even on a
	// would-be cache HIT). recordTx (deferred) emits metrics + closes the tx.
	var tx types.Transaction
	if applyWAF {
		tx = s.waf.get().NewTransaction()
		defer s.recordTx(tx, r)
		if !tx.IsRuleEngineOff() {
			if res := s.wafRequest(tx, r); res.blocked {
				writeBlocked(w, res.status)
				return
			}
		}
	}

	target, strip, isLoc := s.resolveBackend(h, r.URL.Path)
	if target == "" {
		s.log.Warn("edge: no backend for host", "host", domain)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Stream (no buffering, hijack-capable) WebSocket upgrades and explicit
	// streaming clients so we don't break them or buffer unbounded bodies. The WAF
	// request phase already ran; the response phase is bypassed for these.
	if isUpgrade(r) || wantsStream(r) {
		s.stream(w, r, target, strip)
		return
	}

	// Location-matched requests are never cached (they have their own upstreams).
	cacheable := applyCache && !isLoc && requestCacheable(r)

	// Nothing downstream needs a buffered body (no cache store, no WAF response
	// inspection) → stream straight through so a large/long response is never held
	// in memory. The WAF request phase already ran above.
	if !cacheable && !applyWAF {
		s.stream(w, r, target, strip)
		return
	}

	key := r.Method + " " + domain + " " + r.URL.RequestURI()
	if cacheable {
		if raw, ok := s.cache.Get(r.Context(), key); ok {
			if cr, err := decode(raw); err == nil {
				writeResponse(w, cr, "HIT")
				return
			}
		}
	}
	s.serveUpstream(w, r, target, strip, applyWAF, tx, cacheable, key)
}

// serveUpstream proxies to the backend on the buffered path (cacheable response
// and/or WAF response inspection). It buffers at most maxEntryBytes per request:
// a response that fits is inspected, optionally cached, and written; a response
// that exceeds the ceiling is NOT held whole — its buffered prefix is inspected
// (Coraza's own body limit applies anyway) and then prefix+remainder are streamed
// to the client (never truncated, never cached). This bounds per-request heap use.
func (s *Server) serveUpstream(w http.ResponseWriter, r *http.Request, target, strip string, applyWAF bool, tx types.Transaction, cacheable bool, key string) {
	out, err := s.buildUpstreamRequest(r, target, strip)
	if err != nil {
		s.log.Warn("edge: build upstream request", "host", hostOnly(r.Host), "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	resp, err := s.client.Do(out)
	if err != nil {
		// Don't leak the upstream error (internal hostnames/transport detail) to the
		// public client; log it instead.
		s.log.Warn("edge: upstream error", "host", hostOnly(r.Host), "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	hdr := resp.Header.Clone()
	hdr.Del("Connection")
	// Read up to the ceiling + 1 byte so we can tell "fits" from "oversized" without
	// truncating the client's response.
	limit := s.maxEntryBytes
	buf, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		s.log.Warn("edge: read upstream body", "host", hostOnly(r.Host), "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	cr := &cachedResponse{Status: resp.StatusCode, Header: hdr, Body: buf}

	// WAF response phase (runs on the buffered prefix; Coraza caps its own body
	// inspection well under the ceiling, so the prefix is sufficient).
	if applyWAF && !tx.IsRuleEngineOff() {
		if res := s.wafResponse(tx, cr); res.blocked {
			writeBlocked(w, res.status)
			return
		}
	}

	if int64(len(buf)) > limit {
		// Oversized: stream prefix + remaining body; do not buffer or cache it.
		writeStreamedResponse(w, cr, resp.Body)
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

// isUpgrade reports whether the request is a protocol upgrade (e.g. WebSocket),
// which must be streamed (hijacked) rather than buffered.
func isUpgrade(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// wantsStream reports whether the client asked for a streamed response (e.g.
// Server-Sent Events), which must not be buffered.
func wantsStream(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
}

// stream reverse-proxies the request to target with streaming + WebSocket support
// (httputil.ReverseProxy hijacks upgrades and flushes streamed bodies). Existing
// X-Forwarded-* headers from Traefik are preserved.
func (s *Server) stream(w http.ResponseWriter, r *http.Request, target, strip string) {
	tu, err := url.Parse(target)
	if err != nil {
		s.log.Warn("edge stream: bad target", "target", target, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	rp := &httputil.ReverseProxy{
		Transport: s.transport, // shared pool-tuned transport (P1-6)
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(tu)
			if strip != "" {
				pr.Out.URL.Path = stripPath(r.URL.Path, strip)
				pr.Out.URL.RawPath = ""
			}
			pr.Out.Host = r.Host                          // preserve the public Host
			pr.Out.Header.Del(config.EdgeTokenHeader)     // never leak the edge token
			pr.Out.Header.Set("X-Forwarded-Host", r.Host) // mirror the buffered proxy
			pr.Out.Header.Set("X-Forwarded-Proto", schemeOf(r))
		},
		ModifyResponse: func(resp *http.Response) error {
			// Streamed responses bypass the cache; tag them like the buffered path so
			// the X-xgress-Cache header is consistent across every proxied response.
			resp.Header.Set("X-xgress-Cache", "MISS")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			s.log.Warn("edge stream: upstream error", "host", r.Host, "err", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// pickBackend resolves the host's main upstream (round-robin), falling back to
// the first non-empty backend group. Empty when the host has no upstreams.
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
	return s.balance(h.ID, ups)
}

// resolveBackend picks the upstream for a request path. When the path matches a
// host location (longest prefix wins) that location's upstreams are used and its
// strip prefix returned; isLoc reports the match (such requests are not cached).
// WAF-enabled hosts route every path through the edge, so this keeps the WAF on
// location paths instead of letting them bypass to a direct Traefik service.
func (s *Server) resolveBackend(h *store.Host, path string) (target, strip string, isLoc bool) {
	best := -1
	var ups []store.Upstream
	for _, loc := range h.Locations {
		if loc.PathPrefix == "" || len(loc.Upstreams) == 0 {
			continue
		}
		if pathHasPrefix(path, loc.PathPrefix) && len(loc.PathPrefix) > best {
			best = len(loc.PathPrefix)
			ups = loc.Upstreams
			isLoc = true
			if loc.StripPrefix {
				strip = loc.PathPrefix
			} else {
				strip = ""
			}
		}
	}
	if !isLoc {
		return s.pickBackend(h, path), "", false
	}
	return s.balance(h.ID+"\x00"+path[:best], ups), strip, true
}

// balance round-robins across ups using a per-key atomic counter.
func (s *Server) balance(key string, ups []store.Upstream) string {
	if len(ups) == 0 {
		return ""
	}
	ctr, _ := s.rrState.LoadOrStore(key, new(uint64))
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

// pathHasPrefix reports whether path is under the location prefix (segment-aware:
// "/api" matches "/api" and "/api/x" but not "/apix").
func pathHasPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	rest := path[len(prefix):]
	return rest == "" || rest[0] == '/' || strings.HasSuffix(prefix, "/")
}

// stripPath removes a location's strip prefix from the request path, keeping a
// leading slash.
func stripPath(path, prefix string) string {
	if prefix == "" {
		return path
	}
	p := strings.TrimPrefix(path, prefix)
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	return p
}

// cachedResponse is the on-cache representation of an HTTP response.
type cachedResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// buildUpstreamRequest constructs the backend request for the buffered path,
// applying the location strip prefix, copying client headers (minus hop-by-hop
// Connection), and stripping the edge token.
func (s *Server) buildUpstreamRequest(r *http.Request, target, strip string) (*http.Request, error) {
	reqURI := r.URL.RequestURI()
	if strip != "" {
		p := stripPath(r.URL.Path, strip)
		if r.URL.RawQuery != "" {
			p += "?" + r.URL.RawQuery
		}
		reqURI = p
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target+reqURI, r.Body)
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
	return out, nil
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

// writeStreamedResponse writes an oversized response without holding it whole: the
// already-buffered prefix (cr.Body) followed by the streamed remainder. The
// upstream Content-Length (in cr.Header) covers the full body, so prefix+remainder
// match it. Never cached.
func writeStreamedResponse(w http.ResponseWriter, cr *cachedResponse, rest io.Reader) {
	for k, vv := range cr.Header {
		w.Header()[k] = vv
	}
	w.Header().Set("X-xgress-Cache", "MISS")
	w.WriteHeader(cr.Status)
	_, _ = w.Write(cr.Body)
	_, _ = io.Copy(w, rest)
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

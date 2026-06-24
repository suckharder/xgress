package edge

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// TestEdgeTokenGate verifies the edge rejects requests without the token (so a
// network-exposed edge isn't an open proxy), accepts the correct token, and never
// forwards the token to the real backend.
func TestEdgeTokenGate(t *testing.T) {
	var sawToken int32
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(config.EdgeTokenHeader) != "" {
			atomic.StoreInt32(&sawToken, 1)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(be.Close)
	u, _ := url.Parse(be.URL)
	port, _ := strconv.Atoi(u.Port())

	const token = "edge-secret-token"
	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, token, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHosts([]*store.Host{{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"cache.local"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: u.Hostname(), Port: port}},
	}})

	get := func(tok string) int {
		req := httptest.NewRequest(http.MethodGet, "http://cache.local/x", nil)
		req.Host = "cache.local"
		if tok != "" {
			req.Header.Set(config.EdgeTokenHeader, tok)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := get(""); code != http.StatusForbidden {
		t.Errorf("no token = %d, want 403", code)
	}
	if code := get("wrong"); code != http.StatusForbidden {
		t.Errorf("wrong token = %d, want 403", code)
	}
	if code := get(token); code != http.StatusOK {
		t.Errorf("correct token = %d, want 200", code)
	}
	if atomic.LoadInt32(&sawToken) != 0 {
		t.Error("edge token was forwarded to the backend (must be stripped)")
	}
}

// backend returns an httptest server that counts hits and echoes a body, with
// configurable response headers.
func backend(t *testing.T, header http.Header) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		for k, vv := range header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "response-"+strconv.FormatInt(n, 10))
	}))
	t.Cleanup(ts.Close)
	return ts, &hits
}

// edgeFor wires an edge server pointed at the given backend URL for domain.
func edgeFor(t *testing.T, domain, backendURL string, ttl time.Duration) *Server {
	t.Helper()
	u, _ := url.Parse(backendURL)
	port, _ := strconv.Atoi(u.Port())
	s := New(NewMemStore(context.Background(), MemLimits{}), ttl, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHosts([]*store.Host{{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true, Cache: true,
		Domains:   []string{domain},
		Upstreams: []store.Upstream{{Scheme: "http", Host: u.Hostname(), Port: port}},
	}})
	return s
}

func reqTo(s *Server, method, domain, path string) *http.Response {
	req := httptest.NewRequest(method, "http://"+domain+path, nil)
	req.Host = domain
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Result()
}

func TestCacheMissThenHit(t *testing.T) {
	be, hits := backend(t, http.Header{"Cache-Control": {"max-age=60"}})
	s := edgeFor(t, "cache.local", be.URL, time.Minute)

	r1 := reqTo(s, "GET", "cache.local", "/page")
	if r1.Header.Get("X-xgress-Cache") != "MISS" {
		t.Fatalf("first request = %s, want MISS", r1.Header.Get("X-xgress-Cache"))
	}
	b1, _ := io.ReadAll(r1.Body)

	r2 := reqTo(s, "GET", "cache.local", "/page")
	if r2.Header.Get("X-xgress-Cache") != "HIT" {
		t.Fatalf("second request = %s, want HIT", r2.Header.Get("X-xgress-Cache"))
	}
	b2, _ := io.ReadAll(r2.Body)

	if string(b1) != string(b2) {
		t.Errorf("HIT body %q != MISS body %q", b2, b1)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Errorf("backend hit %d times, want 1 (second served from cache)", got)
	}
}

func TestCacheKeyVariesByPathAndDomain(t *testing.T) {
	be, hits := backend(t, http.Header{"Cache-Control": {"max-age=60"}})
	s := edgeFor(t, "cache.local", be.URL, time.Minute)
	// add a second domain pointing at the same backend
	u, _ := url.Parse(be.URL)
	port, _ := strconv.Atoi(u.Port())
	s.SetHosts([]*store.Host{{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true, Cache: true,
		Domains:   []string{"cache.local", "other.local"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: u.Hostname(), Port: port}},
	}})

	reqTo(s, "GET", "cache.local", "/a") // miss
	reqTo(s, "GET", "cache.local", "/b") // different path → miss
	reqTo(s, "GET", "other.local", "/a") // different domain → miss
	reqTo(s, "GET", "cache.local", "/a") // hit

	if got := atomic.LoadInt64(hits); got != 3 {
		t.Errorf("backend hits = %d, want 3 distinct keys", got)
	}
}

func TestUncacheableMethodsAndAuthAlwaysProxy(t *testing.T) {
	be, hits := backend(t, http.Header{"Cache-Control": {"max-age=60"}})
	s := edgeFor(t, "cache.local", be.URL, time.Minute)

	// POST is never cached.
	for i := 0; i < 2; i++ {
		r := reqTo(s, "POST", "cache.local", "/submit")
		if r.Header.Get("X-xgress-Cache") != "MISS" {
			t.Errorf("POST cache header = %s, want MISS", r.Header.Get("X-xgress-Cache"))
		}
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Errorf("POST backend hits = %d, want 2 (never cached)", got)
	}
}

// P0-4: a response larger than the per-request buffer ceiling must be streamed in
// full (never truncated) and never cached — so the edge can't be made to hold N×
// huge responses on the heap.
func TestOversizedResponseStreamsInFullAndIsNotCached(t *testing.T) {
	const bodyLen = 64 * 1024 // 64 KiB, well over the 1 KiB ceiling set below
	var hits int64
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Cache-Control", "max-age=60") // would be cacheable if small enough
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), bodyLen))
	}))
	t.Cleanup(be.Close)
	u, _ := url.Parse(be.URL)
	port, _ := strconv.Atoi(u.Port())

	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetEntryLimit(1024) // ceiling far below the response body
	s.SetHosts([]*store.Host{{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true, Cache: true,
		Domains:   []string{"big.local"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: u.Hostname(), Port: port}},
	}})

	r1 := reqTo(s, "GET", "big.local", "/big")
	b1, _ := io.ReadAll(r1.Body)
	if len(b1) != bodyLen {
		t.Fatalf("streamed body length = %d, want %d (must not be truncated)", len(b1), bodyLen)
	}
	if got := r1.Header.Get("X-xgress-Cache"); got != "MISS" {
		t.Errorf("oversized response cache header = %q, want MISS", got)
	}
	// Second request must hit the backend again — oversized responses are not cached.
	r2 := reqTo(s, "GET", "big.local", "/big")
	_, _ = io.ReadAll(r2.Body)
	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Errorf("backend hits = %d, want 2 (oversized response must not be cached)", got)
	}
}

func TestNoCacheHostReturnsBadGateway(t *testing.T) {
	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := reqTo(s, "GET", "unknown.local", "/")
	if r.StatusCode != http.StatusBadGateway {
		t.Errorf("unknown host = %d, want 502", r.StatusCode)
	}
}

func TestSetHostsSkipsDisabledAndNonProxy(t *testing.T) {
	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetHosts([]*store.Host{
		{ID: "1", Kind: store.HostKindProxy, Enabled: false, Domains: []string{"disabled.local"}},
		{ID: "2", Kind: store.HostKindStream, Enabled: true, Domains: []string{"stream.local"}},
		{ID: "3", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"Active.LOCAL"}},
	})
	if s.host("disabled.local") != nil {
		t.Error("disabled host should not be indexed")
	}
	if s.host("stream.local") != nil {
		t.Error("non-proxy host should not be indexed")
	}
	if s.host("active.local") == nil {
		t.Error("active host should be indexed case-insensitively")
	}
}

func TestResponseTTLRules(t *testing.T) {
	def := 90 * time.Second
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	cases := []struct {
		name    string
		status  int
		header  http.Header
		wantOK  bool
		wantTTL time.Duration
	}{
		{"plain 200 uses default", 200, hdr(), true, def},
		{"non-200 not cached", 404, hdr(), false, 0},
		{"set-cookie not cached", 200, hdr("Set-Cookie", "a=b"), false, 0},
		{"private not cached", 200, hdr("Cache-Control", "private"), false, 0},
		{"no-store not cached", 200, hdr("Cache-Control", "no-store"), false, 0},
		{"max-age honoured", 200, hdr("Cache-Control", "max-age=30"), true, 30 * time.Second},
		{"s-maxage preferred form", 200, hdr("Cache-Control", "s-maxage=45"), true, 45 * time.Second},
		{"max-age=0 not cached", 200, hdr("Cache-Control", "max-age=0"), false, 0},
		{"vary blocks caching", 200, hdr("Vary", "User-Agent"), false, 0},
		{"vary accept-encoding ok", 200, hdr("Vary", "Accept-Encoding"), true, def},
	}
	for _, c := range cases {
		cr := &cachedResponse{Status: c.status, Header: c.header}
		ttl, ok := responseTTL(cr, def)
		if ok != c.wantOK || (ok && ttl != c.wantTTL) {
			t.Errorf("%s: ttl=%v ok=%v, want ttl=%v ok=%v", c.name, ttl, ok, c.wantTTL, c.wantOK)
		}
	}
}

func TestRequestCacheable(t *testing.T) {
	mk := func(method string, h http.Header) *http.Request {
		r := httptest.NewRequest(method, "http://x/", nil)
		for k, vv := range h {
			r.Header[k] = vv
		}
		return r
	}
	if !requestCacheable(mk("GET", nil)) {
		t.Error("plain GET should be cacheable")
	}
	if requestCacheable(mk("POST", nil)) {
		t.Error("POST should not be cacheable")
	}
	if requestCacheable(mk("GET", http.Header{"Authorization": {"Bearer x"}})) {
		t.Error("authorized GET should not be cacheable")
	}
	if requestCacheable(mk("GET", http.Header{"Cache-Control": {"no-store"}})) {
		t.Error("no-store GET should not be cacheable")
	}
}

func TestMaxAgeParsing(t *testing.T) {
	cases := []struct {
		cc   string
		want time.Duration
		ok   bool
	}{
		{"max-age=120", 120 * time.Second, true},
		{"public, max-age=60", 60 * time.Second, true},
		{"s-maxage=10, max-age=60", 10 * time.Second, true}, // s-maxage wins (checked first)
		{"no-cache", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := maxAge(c.cc)
		if ok != c.ok || got != c.want {
			t.Errorf("maxAge(%q) = %v,%v want %v,%v", c.cc, got, ok, c.want, c.ok)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cr := &cachedResponse{
		Status: 200,
		Header: http.Header{"Content-Type": {"text/html"}, "X-Custom": {"a", "b"}},
		Body:   []byte("hello world"),
	}
	raw, err := encode(cr)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != 200 || string(got.Body) != "hello world" {
		t.Errorf("decode mismatch: %+v", got)
	}
	if got.Header.Get("Content-Type") != "text/html" || len(got.Header["X-Custom"]) != 2 {
		t.Errorf("header lost in round-trip: %+v", got.Header)
	}
	if _, err := decode([]byte("not-gob")); err == nil {
		t.Error("decode of garbage should error")
	}
}

func TestPickBackendRoundRobinAndGroups(t *testing.T) {
	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := &store.Host{ID: "rr", Upstreams: []store.Upstream{
		{Scheme: "http", Host: "a", Port: 80},
		{Scheme: "https", Host: "b", Port: 8443},
	}}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		seen[s.pickBackend(h, "/")] = true
	}
	if !seen["http://a:80"] || !seen["https://b:8443"] {
		t.Errorf("round-robin did not hit both upstreams: %v", seen)
	}

	// Falls back to BackendGroups when Upstreams is empty.
	hg := &store.Host{ID: "grp", BackendGroups: []store.BackendGroup{
		{Name: "primary", Upstreams: []store.Upstream{{Host: "c", Port: 9000}}},
	}}
	if got := s.pickBackend(hg, "/"); !strings.Contains(got, "c:9000") {
		t.Errorf("group backend = %q, want c:9000", got)
	}

	// No upstreams → empty string (becomes 502 at ServeHTTP).
	if got := s.pickBackend(&store.Host{ID: "empty"}, "/"); got != "" {
		t.Errorf("empty host backend = %q, want empty", got)
	}
}

func TestNormalizeRedisURL(t *testing.T) {
	cases := map[string]string{
		"redis://h:6379":  "redis://h:6379",
		"h:6379":          "redis://h:6379",
		"redis://h:6379/": "redis://h:6379/",
	}
	for in, want := range cases {
		if got := normalizeRedisURL(in); got != want {
			t.Errorf("normalizeRedisURL(%q) = %q, want %q", in, got, want)
		}
	}
}

var _ = context.Background

func TestEdgeErrorDoesNotLeakUpstream(t *testing.T) {
	s := edgeFor(t, "x.local", "http://127.0.0.1:1", time.Minute) // unreachable backend
	r := reqTo(s, "GET", "x.local", "/")
	if r.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", r.StatusCode)
	}
	b, _ := io.ReadAll(r.Body)
	for _, leak := range []string{"127.0.0.1", "connection refused", "dial", "://"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("edge response leaked internal detail %q: %q", leak, b)
		}
	}
}

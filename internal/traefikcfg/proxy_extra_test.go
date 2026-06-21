package traefikcfg

import (
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/store"
)

func TestRenderProxyLocationsWithStripPrefix(t *testing.T) {
	h := &store.Host{
		ID: "loc", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"app.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSACME,
		Locations: []store.Location{
			{PathPrefix: "/api", StripPrefix: true, Upstreams: []store.Upstream{{Host: "10.0.0.2", Port: 8080}}},
			{PathPrefix: "", Upstreams: []store.Upstream{{Host: "10.0.0.3", Port: 80}}}, // skipped: no prefix
		},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	lr, ok := res.Config.HTTP.Routers["host-loc-loc0"]
	if !ok {
		t.Fatal("expected location router host-loc-loc0")
	}
	if !strings.Contains(lr.Rule, "PathPrefix(`/api`)") {
		t.Errorf("location rule missing path prefix: %s", lr.Rule)
	}
	if lr.Priority <= 1000 {
		t.Errorf("location router should outrank the host router, got priority %d", lr.Priority)
	}
	if res.Config.HTTP.Services["svc-loc-loc0"] == nil {
		t.Error("expected per-location service")
	}
	if res.Config.HTTP.Middlewares["host-loc-loc0-strip"] == nil {
		t.Error("expected strip-prefix middleware for the location")
	}
	if !contains(lr.Middlewares, "host-loc-loc0-strip") {
		t.Errorf("strip middleware not attached: %v", lr.Middlewares)
	}
	// The empty-prefix location must have been skipped.
	if _, ok := res.Config.HTTP.Routers["host-loc-loc1"]; ok {
		t.Error("location with empty prefix must be skipped")
	}
}

func TestRenderCacheEnabledHostRoutesToEdge(t *testing.T) {
	h := &store.Host{
		ID: "cached", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"cdn.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, Cache: true,
	}
	res, err := Render(Inputs{
		Hosts: []*store.Host{h}, EntryPoints: ep(),
		CacheEnabled: true, CacheBackend: "http://127.0.0.1:9100",
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Config.HTTP.Services["svc-cached"]
	if svc == nil || svc.LoadBalancer == nil {
		t.Fatal("expected service for cached host")
	}
	if got := svc.LoadBalancer.Servers[0].URL; got != "http://127.0.0.1:9100" {
		t.Errorf("cache-enabled host must route to the edge, got %q", got)
	}
}

func TestRenderCacheTokenInjectedOnEdgeRoutersOnly(t *testing.T) {
	h := &store.Host{
		ID: "ct", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"cdn.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		Cache:       true,
		CacheAssets: true, // also produces the static-asset edge router
		Locations:   []store.Location{{PathPrefix: "/api", Upstreams: []store.Upstream{{Host: "10.0.0.2", Port: 8080}}}},
	}
	res, err := Render(Inputs{
		Hosts: []*store.Host{h}, EntryPoints: ep(),
		CacheEnabled: true, CacheBackend: "http://xgress:9100", CacheToken: "edge-tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// The shared token middleware is defined and injects the header.
	mw := res.Config.HTTP.Middlewares[cacheTokenMW]
	if mw == nil || mw.Headers == nil || mw.Headers.CustomRequestHeaders["X-xgress-Cache-Token"] != "edge-tok" {
		t.Fatalf("xgress-cache-token middleware missing/wrong: %+v", mw)
	}
	// Edge-targeting routers (main + static-asset) carry the token; the location
	// router (its own non-edge service) must NOT.
	if !contains(res.Config.HTTP.Routers["host-ct"].Middlewares, cacheTokenMW) {
		t.Error("main router missing cache-token middleware")
	}
	if !contains(res.Config.HTTP.Routers["host-ct-static"].Middlewares, cacheTokenMW) {
		t.Error("static-asset router missing cache-token middleware")
	}
	if contains(res.Config.HTTP.Routers["host-ct-loc0"].Middlewares, cacheTokenMW) {
		t.Error("location router must NOT carry the cache-token middleware (routes to its own backend)")
	}
}

func TestRenderNoCacheTokenWithoutToken(t *testing.T) {
	// Cache routed but no token (single-container legacy) → no token middleware.
	h := &store.Host{
		ID: "nt", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"x.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, Cache: true,
	}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep(), CacheEnabled: true, CacheBackend: "http://127.0.0.1:9100"})
	if _, ok := res.Config.HTTP.Middlewares[cacheTokenMW]; ok {
		t.Error("cache-token middleware defined without a token")
	}
	if contains(res.Config.HTTP.Routers["host-nt"].Middlewares, cacheTokenMW) {
		t.Error("router carries cache-token middleware without a token")
	}
}

func TestParseRawConfigReservedTCPPriority(t *testing.T) {
	bad := "tcp:\n  routers:\n    r:\n      rule: \"HostSNI(`*`)\"\n      priority: 1500000\n      service: s\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - address: \"10.0.0.1:5432\"\n"
	if _, err := ParseRawConfig(bad); err == nil {
		t.Error("expected rejection of TCP router priority in the reserved band")
	}
}

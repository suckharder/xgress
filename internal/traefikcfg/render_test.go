package traefikcfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/store"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

func ep() EntryPoints { return EntryPoints{HTTP: "web", HTTPS: "websecure"} }

func TestRenderProxyHostProducesValidConfig(t *testing.T) {
	h := &store.Host{
		ID: "abc", Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"app.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.5", Port: 8080}},
		TLS:       store.TLSACME, ForceTLS: true, HSTS: true,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}

	r, ok := res.Config.HTTP.Routers["host-abc"]
	if !ok {
		t.Fatal("expected router host-abc")
	}
	if r.Rule != "Host(`app.example.com`)" {
		t.Errorf("unexpected rule: %s", r.Rule)
	}
	if len(r.EntryPoints) != 1 || r.EntryPoints[0] != "websecure" {
		t.Errorf("expected websecure entrypoint, got %v", r.EntryPoints)
	}
	if r.TLS == nil {
		t.Error("expected TLS enabled on router")
	}
	// Force-HTTPS adds an http router with a redirect middleware.
	if _, ok := res.Config.HTTP.Routers["host-abc-http"]; !ok {
		t.Error("expected force-TLS redirect router")
	}
	svc := res.Config.HTTP.Services["svc-abc"]
	if svc == nil || len(svc.LoadBalancer.Servers) != 1 || svc.LoadBalancer.Servers[0].URL != "http://10.0.0.5:8080" {
		t.Errorf("unexpected service: %+v", svc)
	}
}

func TestRenderLoadBalancingAndSticky(t *testing.T) {
	h := &store.Host{
		ID: "lb", Kind: store.HostKindProxy, Enabled: true,
		Domains: []string{"lb.example.com"},
		Upstreams: []store.Upstream{
			{Scheme: "http", Host: "10.0.0.1", Port: 80, Weight: 3},
			{Scheme: "http", Host: "10.0.0.2", Port: 80},
		},
		HealthCheckURL: "/health",
		LoadBalancer:   "p2c",
		Sticky:         true,
		TLS:            store.TLSNone,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	lb := res.Config.HTTP.Services["svc-lb"].LoadBalancer
	if len(lb.Servers) != 2 {
		t.Fatalf("expected 2 servers (load balanced), got %d", len(lb.Servers))
	}
	if lb.Servers[0].Weight == nil || *lb.Servers[0].Weight != 3 {
		t.Errorf("expected weight 3 on first server")
	}
	if lb.HealthCheck == nil || lb.HealthCheck.Path != "/health" {
		t.Errorf("expected health check path")
	}
	if lb.Sticky == nil || lb.Sticky.Cookie == nil || lb.Sticky.Cookie.Name != "xgress_lb" {
		t.Errorf("expected sticky cookie, got %+v", lb.Sticky)
	}
	if lb.Strategy != dynamic.BalancerStrategyP2C {
		t.Errorf("expected p2c strategy, got %q", lb.Strategy)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderWeightedCanary(t *testing.T) {
	h := &store.Host{
		ID: "w", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"canary.example.com"},
		TLS: store.TLSNone, ServiceMode: "weighted", Sticky: true,
		BackendGroups: []store.BackendGroup{
			{Name: "v1", Weight: 9, Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}},
			{Name: "v2", Weight: 1, Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.2", Port: 80}}},
		},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	wrr := res.Config.HTTP.Services["svc-w"].Weighted
	if wrr == nil || len(wrr.Services) != 2 {
		t.Fatalf("expected weighted service with 2 children, got %+v", wrr)
	}
	if wrr.Services[0].Name != "svc-w-g0" || *wrr.Services[0].Weight != 9 {
		t.Errorf("unexpected child 0: %+v", wrr.Services[0])
	}
	if wrr.Sticky == nil {
		t.Error("expected sticky on weighted")
	}
	if res.Config.HTTP.Services["svc-w-g0"].LoadBalancer == nil {
		t.Error("expected leaf service svc-w-g0")
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderFailoverAndMirroring(t *testing.T) {
	grp := func(n, host string) store.BackendGroup {
		return store.BackendGroup{Name: n, Upstreams: []store.Upstream{{Scheme: "http", Host: host, Port: 80}}}
	}
	fo := &store.Host{ID: "f", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"f.example.com"}, TLS: store.TLSNone,
		ServiceMode: "failover", HealthCheckURL: "/health", BackendGroups: []store.BackendGroup{grp("p", "10.0.0.1"), grp("b", "10.0.0.2")}}
	mi := &store.Host{ID: "m", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"m.example.com"}, TLS: store.TLSNone,
		ServiceMode: "mirroring", BackendGroups: []store.BackendGroup{grp("main", "10.0.0.1"), {Name: "shadow", Percent: 10, Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.9", Port: 80}}}}}
	res, err := Render(Inputs{Hosts: []*store.Host{fo, mi}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if f := res.Config.HTTP.Services["svc-f"].Failover; f == nil || f.Service != "svc-f-g0" || f.Fallback != "svc-f-g1" {
		t.Errorf("unexpected failover: %+v", res.Config.HTTP.Services["svc-f"].Failover)
	}
	m := res.Config.HTTP.Services["svc-m"].Mirroring
	if m == nil || m.Service != "svc-m-g0" || len(m.Mirrors) != 1 || m.Mirrors[0].Percent != 10 {
		t.Errorf("unexpected mirroring: %+v", m)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderCacheAssets(t *testing.T) {
	h := &store.Host{
		ID: "c", Kind: store.HostKindProxy, Enabled: true,
		Domains:     []string{"cache.example.com"},
		Upstreams:   []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}},
		TLS:         store.TLSNone,
		CacheAssets: true,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	sr, ok := res.Config.HTTP.Routers["host-c-static"]
	if !ok {
		t.Fatal("expected static-asset cache router")
	}
	if !strings.Contains(sr.Rule, "PathRegexp") {
		t.Errorf("expected PathRegexp in static router rule: %s", sr.Rule)
	}
	mw := res.Config.HTTP.Middlewares["host-c-cache"]
	if mw == nil || mw.Headers == nil || mw.Headers.CustomResponseHeaders["Cache-Control"] == "" {
		t.Errorf("expected Cache-Control header middleware")
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderOmitsEmptySections(t *testing.T) {
	// Traefik's provider decoder rejects empty tcp:{}/udp:{} — they must be absent.
	res, err := Render(Inputs{EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(res.JSON, &m); err != nil {
		t.Fatal(err)
	}
	// An all-empty render prunes every section (incl. http) → a bare {} document,
	// which Traefik accepts; an empty "http":{} would be rejected as standalone.
	for _, k := range []string{"http", "tcp", "udp", "tls"} {
		if _, present := m[k]; present {
			t.Errorf("empty section %q must be omitted from served config", k)
		}
	}
}

func TestBuildMiddlewareRejectsUnknownField(t *testing.T) {
	_, err := BuildMiddleware("headers", map[string]any{"notARealField": true})
	if err == nil {
		t.Fatal("expected unknown-field error")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown-field message, got %v", err)
	}
}

func TestBuildMiddlewareValid(t *testing.T) {
	mw, err := BuildMiddleware("rateLimit", map[string]any{"average": 100, "burst": 50})
	if err != nil {
		t.Fatalf("valid middleware rejected: %v", err)
	}
	if mw.RateLimit == nil || mw.RateLimit.Average != 100 {
		t.Errorf("rateLimit not parsed: %+v", mw)
	}
}

func TestInjectKeysReplacesPlaceholder(t *testing.T) {
	cfg := &dynamic.Configuration{}
	_ = cfg
	rendered := []byte(`{"tls":{"certificates":[{"certFile":"CERT","keyFile":"@@KEY:c1"}]}}`)
	out, err := InjectKeys(rendered, func(id string) (string, error) {
		if id != "c1" {
			t.Fatalf("unexpected cert id %s", id)
		}
		return "-----BEGIN KEY-----\nline\n-----END KEY-----\n", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "@@KEY") {
		t.Error("placeholder not replaced")
	}
	// Result must still be valid JSON with the key spliced in.
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("injected output is not valid JSON: %v", err)
	}
}

func TestRenderHostCORS(t *testing.T) {
	h := &store.Host{
		ID: "cors1", Kind: store.HostKindProxy, Enabled: true,
		Domains:              []string{"api.example.com"},
		Upstreams:            []store.Upstream{{Scheme: "http", Host: "10.0.0.7", Port: 8080}},
		TLS:                  store.TLSNone,
		CORSEnabled:          true,
		CORSAllowOrigins:     []string{"https://app.example.com", "https://admin.example.com"},
		CORSAllowCredentials: true,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}

	mw, ok := res.Config.HTTP.Middlewares["host-cors1-cors"]
	if !ok {
		t.Fatal("expected generated middleware host-cors1-cors")
	}
	if mw.Headers == nil {
		t.Fatal("CORS middleware has no Headers config")
	}
	hd := mw.Headers
	if len(hd.AccessControlAllowOriginList) != 2 || hd.AccessControlAllowOriginList[0] != "https://app.example.com" {
		t.Errorf("origin list = %v", hd.AccessControlAllowOriginList)
	}
	if !hd.AccessControlAllowCredentials {
		t.Error("expected AccessControlAllowCredentials true")
	}
	if !hd.AddVaryHeader {
		t.Error("expected AddVaryHeader true so caches vary by Origin")
	}
	if hd.AccessControlMaxAge != 600 {
		t.Errorf("max-age = %d, want 600", hd.AccessControlMaxAge)
	}
	if len(hd.AccessControlAllowMethods) == 0 {
		t.Error("expected default allow-methods")
	}

	// The middleware must be attached to the host's router.
	r, ok := res.Config.HTTP.Routers["host-cors1"]
	if !ok {
		t.Fatal("expected router host-cors1")
	}
	var attached bool
	for _, m := range r.Middlewares {
		if m == "host-cors1-cors" {
			attached = true
		}
	}
	if !attached {
		t.Errorf("CORS middleware not attached to router; chain = %v", r.Middlewares)
	}
}

func TestRenderHostCORSDisabledOrEmpty(t *testing.T) {
	// Disabled: no middleware.
	h := &store.Host{
		ID: "c2", Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"x.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.8", Port: 80}},
		TLS:       store.TLSNone,
		// CORSEnabled false
		CORSAllowOrigins: []string{"https://nope.example.com"},
	}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if _, ok := res.Config.HTTP.Middlewares["host-c2-cors"]; ok {
		t.Error("CORS middleware emitted while disabled")
	}

	// Enabled but no origins: no middleware (defensive; validation also blocks this).
	h2 := &store.Host{
		ID: "c3", Kind: store.HostKindProxy, Enabled: true,
		Domains:     []string{"y.example.com"},
		Upstreams:   []store.Upstream{{Scheme: "http", Host: "10.0.0.9", Port: 80}},
		TLS:         store.TLSNone,
		CORSEnabled: true,
	}
	res2, _ := Render(Inputs{Hosts: []*store.Host{h2}, EntryPoints: ep()})
	if _, ok := res2.Config.HTTP.Middlewares["host-c3-cors"]; ok {
		t.Error("CORS middleware emitted with no origins")
	}
}

func TestRenderStaticProviderToken(t *testing.T) {
	base := StaticParams{
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure", HTTPPort: 80, HTTPSPort: 443,
		ProviderEndpoint: "http://127.0.0.1:9000/api/provider", PollInterval: "1s",
	}
	// With a token: the HTTP provider must carry the auth header.
	withTok := base
	withTok.ProviderToken = "tok-abc123"
	y, err := RenderStatic(withTok)
	if err != nil {
		t.Fatal(err)
	}
	s := string(y)
	if !strings.Contains(s, "X-xgress-Provider-Token") || !strings.Contains(s, "tok-abc123") {
		t.Errorf("static config missing provider token header:\n%s", s)
	}

	// Without a token: no headers block emitted.
	y2, err := RenderStatic(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(y2), "X-xgress-Provider-Token") {
		t.Errorf("static config should not emit a token header when none is set:\n%s", y2)
	}
}

func TestParseRawConfigReservedPriority(t *testing.T) {
	// A raw router invading the reserved band (>= 1_000_000) is rejected.
	bad := "http:\n  routers:\n    r:\n      rule: \"PathPrefix(`/`)\"\n      priority: 2000001\n      service: s\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: \"http://10.0.0.1\"\n"
	if _, err := ParseRawConfig(bad); err == nil {
		t.Error("expected rejection of router priority >= ReservedRouterPriority")
	}
	// A normal priority is accepted.
	ok := "http:\n  routers:\n    r:\n      rule: \"PathPrefix(`/`)\"\n      priority: 5000\n      service: s\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: \"http://10.0.0.1\"\n"
	if _, err := ParseRawConfig(ok); err != nil {
		t.Errorf("valid raw config rejected: %v", err)
	}
}

func TestPerHostRawDropsRouters(t *testing.T) {
	h := &store.Host{
		ID: "raw1", Kind: store.HostKindProxy, Enabled: true,
		Domains:   []string{"raw.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.5", Port: 80}},
		TLS:       store.TLSNone,
		RawYAML: "http:\n  middlewares:\n    m1:\n      headers:\n        customRequestHeaders:\n          X-T: \"1\"\n" +
			"  routers:\n    evil:\n      rule: \"PathPrefix(`/`)\"\n      priority: 5000\n      service: s1\n" +
			"  services:\n    s1:\n      loadBalancer:\n        servers:\n          - url: \"http://10.0.0.9\"\n",
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// The raw middleware is merged + attached; the raw router is DROPPED.
	if _, ok := res.Config.HTTP.Middlewares["host-raw1-raw-m1"]; !ok {
		t.Error("expected raw middleware host-raw1-raw-m1 to be merged")
	}
	if _, ok := res.Config.HTTP.Routers["host-raw1-raw-evil"]; ok {
		t.Error("raw router was merged into config — per-host raw must NOT inject routers")
	}
}

func TestInjectKeysIgnoresCertContentSentinel(t *testing.T) {
	// keyFile placeholder is replaced; a "@@KEY:" sentinel embedded in certFile
	// content (attacker-controlled) must NOT trigger a resolve or break serving.
	rendered := []byte(`{"tls":{"certificates":[{"certFile":"-----BEGIN CERT @@KEY:evil-----","keyFile":"@@KEY:c1"}]}}`)
	out, err := InjectKeys(rendered, func(id string) (string, error) {
		if id != "c1" {
			t.Fatalf("resolver called with %q — certFile sentinel leaked into key injection", id)
		}
		return "PRIVKEY-PEM", nil
	})
	if err != nil {
		t.Fatalf("InjectKeys: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "PRIVKEY-PEM") {
		t.Error("real key not injected")
	}
	if strings.Contains(s, "@@KEY:c1") {
		t.Error("keyFile placeholder not replaced")
	}
	if !strings.Contains(s, "@@KEY:evil") {
		t.Error("certFile content was altered (should be left intact)")
	}
}

func TestInjectKeysOmitsUnresolvableCert(t *testing.T) {
	// c1 resolves; c2 fails. The provider doc must still serve c1 (not error out),
	// and omit c2 — one bad cert must not blank the whole served config.
	rendered := []byte(`{"http":{"routers":{}},"tls":{"certificates":[{"certFile":"A","keyFile":"@@KEY:c1"},{"certFile":"BBB","keyFile":"@@KEY:c2"}]}}`)
	failResolve := func(id string) (string, error) {
		if id == "c1" {
			return "KEY-ONE", nil
		}
		return "", &resolveErr{id}
	}
	out, err := InjectKeys(rendered, failResolve)
	if err != nil {
		t.Fatalf("InjectKeys must not error when one cert fails: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "KEY-ONE") {
		t.Error("resolvable cert (c1) not served")
	}
	if strings.Contains(s, "@@KEY:c2") || strings.Contains(s, `"BBB"`) {
		t.Error("unresolvable cert (c2) must be omitted")
	}
	var v map[string]any
	if json.Unmarshal(out, &v) != nil {
		t.Fatal("output is not valid JSON")
	}
	if _, ok := v["http"]; !ok {
		t.Error("non-tls sections must be preserved")
	}
}

type resolveErr struct{ id string }

func (e *resolveErr) Error() string { return "cannot resolve " + e.id }

func TestBanRouterUsesSingleMatcher(t *testing.T) {
	res, err := Render(Inputs{
		EntryPoints: ep(), ContentBackend: "http://127.0.0.1:9000",
		BannedIPs: []string{"1.1.1.1", "2.2.2.2", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := res.Config.HTTP.Routers["xgress-banned-http"]
	if !ok {
		t.Fatal("expected xgress-banned-http router")
	}
	if strings.Contains(r.Rule, "||") {
		t.Errorf("ban rule still uses an OR-chain: %s", r.Rule)
	}
	if n := strings.Count(r.Rule, "ClientIP("); n != 1 {
		t.Errorf("expected exactly one ClientIP matcher, got %d: %s", n, r.Rule)
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "10.0.0.0/8"} {
		if !strings.Contains(r.Rule, ip) {
			t.Errorf("rule missing %s: %s", ip, r.Rule)
		}
	}
}

package traefikcfg

import (
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// --- WAF routing (native, in-edge) -------------------------------------------

const edgeURL = "http://127.0.0.1:9100"

func TestRenderWAFHostRoutesToEdge(t *testing.T) {
	h := &store.Host{
		ID: "waf1", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"waf.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, WAF: true,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, WAFEnabled: true, EntryPoints: ep(),
		CacheBackend: edgeURL, CacheToken: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	// The WAF is no longer a Traefik middleware — it runs in the edge, so the host's
	// service must point at the edge and carry the edge token middleware.
	if _, ok := res.Config.HTTP.Middlewares["xgress-waf"]; ok {
		t.Error("there must be no xgress-waf middleware (the WAF is native, not a plugin)")
	}
	svc := res.Config.HTTP.Services["svc-waf1"]
	if svc == nil || svc.LoadBalancer == nil || len(svc.LoadBalancer.Servers) == 0 || svc.LoadBalancer.Servers[0].URL != edgeURL {
		t.Fatalf("WAF host service must route to the edge, got %+v", svc)
	}
	r := res.Config.HTTP.Routers["host-waf1"]
	if !contains(r.Middlewares, cacheTokenMW) {
		t.Errorf("edge-routed host must carry the edge token middleware, got %v", r.Middlewares)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderWAFHostDirectWhenGloballyDisabled(t *testing.T) {
	// Host wants WAF but the feature is globally off → it does NOT route to the edge.
	h := &store.Host{ID: "waf2", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"w2.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, WAF: true}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, WAFEnabled: false, EntryPoints: ep(),
		CacheBackend: edgeURL, CacheToken: "tok"})
	svc := res.Config.HTTP.Services["svc-waf2"]
	if svc != nil && svc.LoadBalancer != nil && len(svc.LoadBalancer.Servers) > 0 && svc.LoadBalancer.Servers[0].URL == edgeURL {
		t.Error("disabled WAF host must not route to the edge")
	}
	if contains(res.Config.HTTP.Routers["host-waf2"].Middlewares, cacheTokenMW) {
		t.Error("edge token must not be attached when the host doesn't route to the edge")
	}
}

func TestRenderWAFHostLocationsRoutedThroughEdge(t *testing.T) {
	// A WAF host with locations must NOT emit a separate direct location router
	// (which would bypass the WAF) — the edge resolves location backends itself.
	h := &store.Host{
		ID: "waf3", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"w3.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, WAF: true,
		Locations: []store.Location{{PathPrefix: "/api", Upstreams: []store.Upstream{{Host: "10.0.0.2", Port: 80}}}},
	}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, WAFEnabled: true, EntryPoints: ep(),
		CacheBackend: edgeURL, CacheToken: "tok"})
	if _, ok := res.Config.HTTP.Routers["host-waf3-loc0"]; ok {
		t.Error("WAF host must not emit a direct location router (would bypass the WAF)")
	}
}

// --- middleware catalog ------------------------------------------------------

func TestMiddlewareCatalogExamplesAreReal(t *testing.T) {
	cat := MiddlewareCatalog()
	if len(cat) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, e := range cat {
		if e.Type == "" || e.Label == "" {
			t.Errorf("catalog entry missing type/label: %+v", e)
		}
		if seen[e.Type] {
			t.Errorf("duplicate catalog type %q", e.Type)
		}
		seen[e.Type] = true
		// Every advertised example must decode into the real Traefik struct — this
		// is the guarantee the UI relies on (the example is a valid starting point).
		if _, err := BuildMiddleware(e.Type, e.Example); err != nil {
			t.Errorf("catalog example for %q does not build: %v", e.Type, err)
		}
	}
}

// --- static config (protoOrTCP + sections) -----------------------------------

func TestRenderStaticStreamEntrypointsAndExtras(t *testing.T) {
	p := StaticParams{
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure", HTTPPort: 80, HTTPSPort: 443,
		ProviderEndpoint: "http://127.0.0.1:9000/api/provider", PollInterval: "1s",
		APIListen:   "127.0.0.1:8099",
		AccessLog:   true,
		MetricsProm: true,
		StreamEntryPoints: []config.StreamEntryPoint{
			{Name: "postgres", Port: 5432, Proto: "tcp"},
			{Name: "dns", Port: 53, Proto: "udp"},
		},
	}
	y, err := RenderStatic(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(y)
	// protoOrTCP normalisation: tcp address + udp address.
	if !strings.Contains(s, ":5432/tcp") {
		t.Errorf("missing tcp stream entrypoint:\n%s", s)
	}
	if !strings.Contains(s, ":53/udp") {
		t.Errorf("missing udp stream entrypoint:\n%s", s)
	}
	if !strings.Contains(s, "127.0.0.1:8099") || !strings.Contains(s, "insecure: true") {
		t.Errorf("traefik API entrypoint not enabled:\n%s", s)
	}
	if !strings.Contains(s, "accessLog") {
		t.Error("accessLog block missing")
	}
	if !strings.Contains(s, "prometheus") {
		t.Error("prometheus metrics block missing")
	}
	if strings.Contains(s, "experimental") {
		t.Error("no Traefik plugins should be declared (the WAF is native)")
	}
}

func TestRenderStaticMinimal_OmitsExtras(t *testing.T) {
	// The self-heal minimal config: entrypoints + provider only, no API/metrics/
	// accessLog/stream entrypoints.
	y, err := RenderStatic(StaticParams{
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure", HTTPPort: 80, HTTPSPort: 443,
		ProviderEndpoint: "http://127.0.0.1:9000/api/provider", PollInterval: "1s",
		APIListen: "127.0.0.1:8099", AccessLog: true, MetricsProm: true,
		StreamEntryPoints: []config.StreamEntryPoint{{Name: "postgres", Port: 5432, Proto: "tcp"}},
		Minimal:           true,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(y)
	for _, banned := range []string{"insecure: true", "prometheus", "accessLog", ":5432", "experimental"} {
		if strings.Contains(s, banned) {
			t.Errorf("minimal static config must omit %q:\n%s", banned, s)
		}
	}
	// But the essentials must remain.
	if !strings.Contains(s, "/api/provider") || !strings.Contains(s, ":80") || !strings.Contains(s, ":443") {
		t.Errorf("minimal static config missing entrypoints/provider:\n%s", s)
	}
}

func TestRenderStaticMinimal(t *testing.T) {
	// No API, no plugins, no extras → those blocks must be absent.
	y, err := RenderStatic(StaticParams{
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure", HTTPPort: 80, HTTPSPort: 443,
		ProviderEndpoint: "http://127.0.0.1:9000/api/provider", PollInterval: "1s",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(y)
	if strings.Contains(s, "experimental") {
		t.Error("no plugins → experimental block must be absent")
	}
	if strings.Contains(s, "accessLog") || strings.Contains(s, "prometheus") {
		t.Error("extras must be absent when disabled")
	}
	if !strings.Contains(s, "level: INFO") {
		t.Error("log level should default to INFO")
	}
}

// --- HashBytes ---------------------------------------------------------------

func TestHashBytes(t *testing.T) {
	a := HashBytes([]byte("hello"))
	b := HashBytes([]byte("hello"))
	c := HashBytes([]byte("world"))
	if a != b {
		t.Error("hash must be deterministic")
	}
	if a == c {
		t.Error("different inputs must hash differently")
	}
	if len(a) != 64 {
		t.Errorf("sha-256 hex must be 64 chars, got %d", len(a))
	}
}

// --- Render error path -------------------------------------------------------

func TestRenderRejectsInvalidMiddleware(t *testing.T) {
	bad := &store.Middleware{ID: "m", Name: "broken", Type: "headers", Params: map[string]any{"nope": 1}}
	if _, err := Render(Inputs{Middlewares: []*store.Middleware{bad}, EntryPoints: ep()}); err == nil {
		t.Fatal("render must fail when a user middleware does not validate")
	}
}

package traefikcfg

import (
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// --- WAF plugin --------------------------------------------------------------

func TestDefaultWAFDirectives(t *testing.T) {
	d := DefaultWAFDirectives()
	if len(d) == 0 {
		t.Fatal("default WAF directives must not be empty")
	}
	if d[0] != "SecRuleEngine On" {
		t.Errorf("ruleset must start by enabling the engine, got %q", d[0])
	}
	joined := strings.Join(d, "\n")
	// Sanity: the curated ruleset covers the headline attack classes.
	for _, want := range []string{"SQL injection", "XSS", "Path traversal", "Scanner user-agent"} {
		if !strings.Contains(joined, want) {
			t.Errorf("default ruleset missing a %q rule", want)
		}
	}
}

func TestWAFMiddlewareDefaultsAndAudit(t *testing.T) {
	// Empty directives → falls back to the default ruleset, with audit prepended.
	mw := wafMiddleware(nil)
	conf, ok := mw.Plugin[WAFPluginName]
	if !ok {
		t.Fatalf("WAF middleware must reference the %q plugin", WAFPluginName)
	}
	dirs, ok := conf["directives"].([]string)
	if !ok || len(dirs) == 0 {
		t.Fatalf("expected directives slice, got %T", conf["directives"])
	}
	if dirs[0] != "SecAuditEngine RelevantOnly" {
		t.Errorf("audit directives must be first so blocks surface as metrics, got %q", dirs[0])
	}
	if !strings.Contains(strings.Join(dirs, "\n"), "SecRuleEngine On") {
		t.Error("default ruleset not appended after audit directives")
	}

	// Custom directives → used verbatim after the audit block.
	custom := wafMiddleware([]string{"SecRuleEngine On", "SecRule ARGS \"@rx custom\" \"id:9001,phase:2,deny\""})
	cdirs := custom.Plugin[WAFPluginName]["directives"].([]string)
	if !strings.Contains(strings.Join(cdirs, "\n"), "id:9001") {
		t.Error("custom directive not present")
	}
	if cdirs[0] != "SecAuditEngine RelevantOnly" {
		t.Error("audit block must precede custom directives")
	}
}

func TestRenderWAFAttachedToHost(t *testing.T) {
	h := &store.Host{
		ID: "waf1", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"waf.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, WAF: true,
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, WAFEnabled: true, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Config.HTTP.Middlewares["xgress-waf"]; !ok {
		t.Fatal("expected shared xgress-waf middleware")
	}
	r := res.Config.HTTP.Routers["host-waf1"]
	if len(r.Middlewares) == 0 || r.Middlewares[0] != "xgress-waf" {
		t.Errorf("WAF must be the first (security-gate) middleware, got %v", r.Middlewares)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderWAFNotAttachedWhenGloballyDisabled(t *testing.T) {
	// Host wants WAF but the feature is globally off → no WAF middleware/attachment.
	h := &store.Host{ID: "waf2", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"w2.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, WAF: true}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, WAFEnabled: false, EntryPoints: ep()})
	if _, ok := res.Config.HTTP.Middlewares["xgress-waf"]; ok {
		t.Error("xgress-waf must not be defined when the WAF feature is disabled")
	}
	if contains(res.Config.HTTP.Routers["host-waf2"].Middlewares, "xgress-waf") {
		t.Error("WAF must not be attached when globally disabled")
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
		Plugins: []PluginDecl{{Name: WAFPluginName, ModuleName: WAFModuleName, Version: WAFModuleVersion}},
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
	if !strings.Contains(s, WAFModuleName) || !strings.Contains(s, "experimental") {
		t.Error("plugin declaration missing")
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

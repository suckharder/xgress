package traefikcfg

import (
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/store"
)

// --- renderRedirectionHost ---------------------------------------------------

func TestRenderRedirectionHostDefaults(t *testing.T) {
	h := &store.Host{
		ID: "r1", Kind: store.HostKindRedirection, Enabled: true,
		Domains:    []string{"old.example.com"},
		RedirectTo: "https://new.example.com",
		TLS:        store.TLSNone,
		// RedirectCode unset → defaults to 308 (permanent).
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}

	mw, ok := res.Config.HTTP.Middlewares["host-r1-redirect"]
	if !ok || mw.RedirectRegex == nil {
		t.Fatalf("expected redirectRegex middleware, got %+v", mw)
	}
	if !mw.RedirectRegex.Permanent {
		t.Error("default code 308 must render Permanent=true")
	}
	if mw.RedirectRegex.Replacement != "https://new.example.com" {
		t.Errorf("replacement = %q (keep-path off should replace the whole URL)", mw.RedirectRegex.Replacement)
	}
	r, ok := res.Config.HTTP.Routers["host-r1"]
	if !ok {
		t.Fatal("expected router host-r1")
	}
	if r.Service != "noop" {
		t.Errorf("redirection router should target the noop service, got %q", r.Service)
	}
	if len(r.EntryPoints) != 1 || r.EntryPoints[0] != "web" {
		t.Errorf("TLS off → HTTP entrypoint expected, got %v", r.EntryPoints)
	}
	if r.TLS != nil {
		t.Error("TLS off → router must not enable TLS")
	}
	if r.Middlewares[0] != "host-r1-redirect" {
		t.Errorf("redirect middleware must be first in chain, got %v", r.Middlewares)
	}
	// The shared noop service must exist exactly once.
	if res.Config.HTTP.Services["noop"] == nil {
		t.Error("expected shared noop service")
	}
}

func TestRenderRedirectionHostKeepPathAndTemporary(t *testing.T) {
	h := &store.Host{
		ID: "r2", Kind: store.HostKindRedirection, Enabled: true,
		Domains:          []string{"a.example.com"},
		RedirectTo:       "https://b.example.com/",
		RedirectCode:     302,
		RedirectKeepPath: true,
		TLS:              store.TLSACME, // → HTTPS entrypoint + router TLS
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	mw := res.Config.HTTP.Middlewares["host-r2-redirect"]
	if mw.RedirectRegex.Permanent {
		t.Error("code 302 must be a temporary (Permanent=false) redirect")
	}
	if want := "https://b.example.com${1}"; mw.RedirectRegex.Replacement != want {
		t.Errorf("keep-path replacement = %q, want %q (trailing slash trimmed + capture group)", mw.RedirectRegex.Replacement, want)
	}
	r := res.Config.HTTP.Routers["host-r2"]
	if r.TLS == nil || len(r.EntryPoints) != 1 || r.EntryPoints[0] != "websecure" {
		t.Errorf("TLS on → HTTPS entrypoint + router TLS expected, got ep=%v tls=%v", r.EntryPoints, r.TLS)
	}
}

func TestRenderRedirectionHostChainsUserMiddleware(t *testing.T) {
	mw := &store.Middleware{ID: "mw1", Name: "compress", Type: "compress", Params: map[string]any{}}
	h := &store.Host{
		ID: "r3", Kind: store.HostKindRedirection, Enabled: true,
		Domains: []string{"c.example.com"}, RedirectTo: "https://d.example.com",
		TLS: store.TLSNone, MiddlewareIDs: []string{"mw1"},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, Middlewares: []*store.Middleware{mw}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Config.HTTP.Routers["host-r3"]
	if len(r.Middlewares) != 2 || r.Middlewares[0] != "host-r3-redirect" || r.Middlewares[1] != "mw-mw1" {
		t.Errorf("expected [redirect, user-mw] chain, got %v", r.Middlewares)
	}
}

// --- renderDeadHost ----------------------------------------------------------

func TestRenderDeadHost(t *testing.T) {
	h := &store.Host{ID: "d1", Kind: store.HostKindDead, Enabled: true, Domains: []string{"dead.example.com"}}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	r, ok := res.Config.HTTP.Routers["host-d1"]
	if !ok {
		t.Fatal("expected router host-d1")
	}
	if r.Priority != 1 {
		t.Errorf("dead host must be lowest priority (1), got %d", r.Priority)
	}
	if len(r.EntryPoints) != 2 {
		t.Errorf("dead host should listen on both entrypoints, got %v", r.EntryPoints)
	}
	if r.Service != "noop" || res.Config.HTTP.Services["noop"] == nil {
		t.Error("dead host must target the shared noop service")
	}
}

func TestNoopServiceSharedAcrossHosts(t *testing.T) {
	// Two hosts that both need the noop service must not double-register / panic.
	h1 := &store.Host{ID: "x", Kind: store.HostKindRedirection, Enabled: true, Domains: []string{"x.example.com"}, RedirectTo: "https://z.example.com", TLS: store.TLSNone}
	h2 := &store.Host{ID: "y", Kind: store.HostKindDead, Enabled: true, Domains: []string{"y.example.com"}}
	res, err := Render(Inputs{Hosts: []*store.Host{h1, h2}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.HTTP.Services["noop"] == nil {
		t.Fatal("expected one shared noop service")
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// --- renderStreamHost --------------------------------------------------------

func TestRenderStreamHostTCP(t *testing.T) {
	h := &store.Host{
		ID: "s1", Kind: store.HostKindStream, Enabled: true,
		StreamProto: "tcp", StreamEntryPoint: "postgres",
		Upstreams: []store.Upstream{{Host: "10.0.0.5", Port: 5432}},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Config.TCP.Services["svc-s1"]
	if svc == nil || svc.LoadBalancer == nil || svc.LoadBalancer.Servers[0].Address != "10.0.0.5:5432" {
		t.Fatalf("unexpected TCP service: %+v", svc)
	}
	r := res.Config.TCP.Routers["host-s1"]
	if r == nil || r.Rule != "HostSNI(`*`)" {
		t.Errorf("expected catch-all HostSNI(`*`), got %+v", r)
	}
	if r.TLS != nil {
		t.Error("non-passthrough TCP must not set TLS")
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderStreamHostTCPPassthrough(t *testing.T) {
	h := &store.Host{
		ID: "s2", Kind: store.HostKindStream, Enabled: true,
		StreamProto: "tcp", StreamEntryPoint: "https-passthrough",
		Domains:        []string{"secure.example.com", "alt.example.com"},
		TLSPassthrough: true,
		Upstreams:      []store.Upstream{{Host: "10.0.0.6", Port: 8443}},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Config.TCP.Routers["host-s2"]
	if r == nil {
		t.Fatal("expected TCP router")
	}
	if r.TLS == nil || !r.TLS.Passthrough {
		t.Error("expected TLS passthrough enabled")
	}
	// SNI rule must enumerate both domains (passthrough disallows HostSNI(`*`)).
	for _, d := range []string{"secure.example.com", "alt.example.com"} {
		if !strings.Contains(r.Rule, d) {
			t.Errorf("SNI rule missing %s: %s", d, r.Rule)
		}
	}
	if !strings.Contains(r.Rule, "||") {
		t.Errorf("multi-SNI rule should OR the domains: %s", r.Rule)
	}
}

func TestRenderStreamHostUDP(t *testing.T) {
	h := &store.Host{
		ID: "s3", Kind: store.HostKindStream, Enabled: true,
		StreamProto: "udp", StreamEntryPoint: "dns",
		Upstreams: []store.Upstream{{Host: "10.0.0.53", Port: 53}},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	svc := res.Config.UDP.Services["svc-s3"]
	if svc == nil || svc.LoadBalancer.Servers[0].Address != "10.0.0.53:53" {
		t.Fatalf("unexpected UDP service: %+v", svc)
	}
	if res.Config.UDP.Routers["host-s3"] == nil {
		t.Fatal("expected UDP router host-s3")
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRenderStreamHostIncompleteIsSkipped(t *testing.T) {
	// No upstreams, or no entrypoint → nothing rendered (and no empty TCP section).
	noUp := &store.Host{ID: "s4", Kind: store.HostKindStream, Enabled: true, StreamProto: "tcp", StreamEntryPoint: "x"}
	noEp := &store.Host{ID: "s5", Kind: store.HostKindStream, Enabled: true, StreamProto: "tcp", Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 1}}}
	res, err := Render(Inputs{Hosts: []*store.Host{noUp, noEp}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Config.TCP != nil {
		t.Errorf("incomplete stream hosts should render nothing (TCP section must be pruned), got %+v", res.Config.TCP)
	}
}

func TestRenderDisabledHostSkipped(t *testing.T) {
	h := &store.Host{ID: "off", Kind: store.HostKindProxy, Enabled: false, Domains: []string{"off.example.com"}, Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing else is configured, so the (empty) HTTP section is pruned to nil — which
	// itself proves the disabled host produced no router. Guard the nil before checking.
	if res.Config.HTTP != nil {
		if _, ok := res.Config.HTTP.Routers["host-off"]; ok {
			t.Error("disabled host must not be rendered")
		}
	}
}

package traefikcfg

import (
	"strings"
	"testing"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"

	"github.com/suckharder/xgress/internal/store"
)

// --- ValidateMiddleware ------------------------------------------------------

func TestValidateMiddleware(t *testing.T) {
	if issues := ValidateMiddleware("rateLimit", map[string]any{"average": 100, "burst": 10}); issues != nil {
		t.Errorf("valid middleware reported issues: %v", issues)
	}
	issues := ValidateMiddleware("headers", map[string]any{"bogusField": true})
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for unknown field, got %v", issues)
	}
	if issues[0].Field != "headers" || !strings.Contains(issues[0].Message, "unknown field") {
		t.Errorf("unexpected issue: %+v", issues[0])
	}
	if issues := ValidateMiddleware("", nil); len(issues) != 1 {
		t.Errorf("empty type must be rejected, got %v", issues)
	}
}

// --- ValidateHostInputs ------------------------------------------------------

type fakeUp struct{ scheme, host string }

func (u fakeUp) GetScheme() string { return u.scheme }
func (u fakeUp) GetHost() string   { return u.host }

func TestValidateHostInputsProxy(t *testing.T) {
	// Happy path: no issues.
	if issues := ValidateHostInputs("proxy", []string{"ok.example.com"}, []fakeUp{{"https", "10.0.0.1"}}, ""); len(issues) != 0 {
		t.Errorf("valid proxy reported issues: %v", issues)
	}
	// Missing domains + upstreams.
	issues := ValidateHostInputs("proxy", nil, []fakeUp{}, "")
	if !hasField(issues, "domains") || !hasField(issues, "upstreams") {
		t.Errorf("expected domains+upstreams issues, got %v", issues)
	}
	// Empty upstream host + bad scheme.
	issues = ValidateHostInputs("proxy", []string{"x.example.com"}, []fakeUp{{"ftp", ""}}, "")
	if !hasField(issues, "upstreams[0].host") || !hasField(issues, "upstreams[0].scheme") {
		t.Errorf("expected host+scheme issues, got %v", issues)
	}
	// h2c is an allowed scheme.
	if issues := ValidateHostInputs("proxy", []string{"x.example.com"}, []fakeUp{{"h2c", "10.0.0.1"}}, ""); hasField(issues, "upstreams[0].scheme") {
		t.Errorf("h2c must be an allowed scheme, got %v", issues)
	}
}

func TestValidateHostInputsRedirection(t *testing.T) {
	if issues := ValidateHostInputs("redirection", []string{"a.example.com"}, []fakeUp{}, "https://b.example.com"); len(issues) != 0 {
		t.Errorf("valid redirection reported issues: %v", issues)
	}
	// Missing target.
	if issues := ValidateHostInputs("redirection", []string{"a.example.com"}, []fakeUp{}, ""); !hasField(issues, "redirectTo") {
		t.Errorf("missing redirect target must be flagged, got %v", issues)
	}
	// Non-absolute URL.
	if issues := ValidateHostInputs("redirection", []string{"a.example.com"}, []fakeUp{}, "not a url"); !hasField(issues, "redirectTo") {
		t.Errorf("invalid redirect URL must be flagged, got %v", issues)
	}
}

func TestValidateHostInputsDomainShape(t *testing.T) {
	// Domain character validation moved to ValidateRuleInputs (so every host kind/mode
	// gets it, not just the single-service path). ValidateHostInputs keeps the
	// semantic checks (domain count, upstreams, redirect URL).
	issues := ValidateRuleInputs([]string{"bad domain", "with/slash"}, nil)
	if !hasField(issues, "domains[0]") || !hasField(issues, "domains[1]") {
		t.Errorf("malformed domains must be flagged, got %v", issues)
	}
}

func hasField(issues []ValidationIssue, field string) bool {
	for _, i := range issues {
		if i.Field == field {
			return true
		}
	}
	return false
}

// --- CheckRawServiceTargets (SSRF guard on raw passthrough) -------------------

func TestCheckRawServiceTargets(t *testing.T) {
	mk := func(url string) *dynamic.Configuration {
		return &dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{Services: map[string]*dynamic.Service{
			"s": {LoadBalancer: &dynamic.ServersLoadBalancer{Servers: []dynamic.Server{{URL: url}}}},
		}}}
	}
	// Loopback / metadata targets in raw config must be rejected.
	for _, bad := range []string{"http://127.0.0.1:9000", "http://169.254.169.254/latest"} {
		if err := CheckRawServiceTargets(mk(bad)); err == nil {
			t.Errorf("expected rejection of raw service target %q", bad)
		}
	}
	// A public/private routable target is allowed (normal reverse-proxy use).
	if err := CheckRawServiceTargets(mk("http://10.0.0.5:8080")); err != nil {
		t.Errorf("private upstream should be allowed in raw config: %v", err)
	}
	// Nil / empty configs are no-ops.
	if err := CheckRawServiceTargets(nil); err != nil {
		t.Errorf("nil config: %v", err)
	}
	if err := CheckRawServiceTargets(&dynamic.Configuration{}); err != nil {
		t.Errorf("empty config: %v", err)
	}
}

// --- access lists, satisfy-any, error pages ----------------------------------

func TestRenderAccessListBasicAuthAndIP(t *testing.T) {
	acl := &store.AccessList{
		ID: "a1", Name: "team",
		Users:    []store.AccessListUser{{Username: "alice", Hash: "$2y$bcrypthash"}},
		AllowIPs: []string{"10.0.0.0/8"},
	}
	h := &store.Host{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"app.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		AccessListIDs: []string{"a1"},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, AccessLists: []*store.AccessList{acl}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	auth := res.Config.HTTP.Middlewares["acl-a1-auth"]
	if auth == nil || auth.BasicAuth == nil || auth.BasicAuth.Users[0] != "alice:$2y$bcrypthash" {
		t.Errorf("unexpected basic-auth middleware: %+v", auth)
	}
	ip := res.Config.HTTP.Middlewares["acl-a1-ip"]
	if ip == nil || ip.IPAllowList == nil || ip.IPAllowList.SourceRange[0] != "10.0.0.0/8" {
		t.Errorf("unexpected ip-allow middleware: %+v", ip)
	}
	// Both must be attached to the host router (ip then auth).
	r := res.Config.HTTP.Routers["host-h1"]
	if !contains(r.Middlewares, "acl-a1-ip") || !contains(r.Middlewares, "acl-a1-auth") {
		t.Errorf("access-list middlewares not attached: %v", r.Middlewares)
	}
}

func TestRenderSatisfyAnyBypass(t *testing.T) {
	acl := &store.AccessList{
		ID: "a2", Name: "office", SatisfyAny: true,
		Users:    []store.AccessListUser{{Username: "bob", Hash: "$2y$h"}},
		AllowIPs: []string{"203.0.113.0/24"},
	}
	h := &store.Host{
		ID: "h2", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"intranet.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSACME,
		AccessListIDs: []string{"a2"},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, AccessLists: []*store.AccessList{acl}, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	trusted, ok := res.Config.HTTP.Routers["host-h2-trusted"]
	if !ok {
		t.Fatal("expected satisfy-any bypass router host-h2-trusted")
	}
	if trusted.Priority != 2000 {
		t.Errorf("bypass router priority = %d, want 2000", trusted.Priority)
	}
	if !strings.Contains(trusted.Rule, "203.0.113.0/24") {
		t.Errorf("bypass rule missing trusted range: %s", trusted.Rule)
	}
	// The bypass router must DROP the auth + ip middlewares (trusted IPs skip auth).
	if contains(trusted.Middlewares, "acl-a2-auth") || contains(trusted.Middlewares, "acl-a2-ip") {
		t.Errorf("bypass router must not carry the auth/ip middlewares, got %v", trusted.Middlewares)
	}
	if trusted.TLS == nil {
		t.Error("bypass router should inherit TLS from the host")
	}
}

func TestRenderSatisfyAnyRequiresBothAuthAndIP(t *testing.T) {
	// SatisfyAny with only IPs (no users) → no bypass router (nothing to bypass).
	acl := &store.AccessList{ID: "a3", SatisfyAny: true, AllowIPs: []string{"10.0.0.0/8"}}
	h := &store.Host{ID: "h3", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"x.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone, AccessListIDs: []string{"a3"}}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, AccessLists: []*store.AccessList{acl}, EntryPoints: ep()})
	if _, ok := res.Config.HTTP.Routers["host-h3-trusted"]; ok {
		t.Error("satisfy-any with no users should not produce a bypass router")
	}
}

func TestRenderErrorPages(t *testing.T) {
	h := &store.Host{
		ID: "h4", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"site.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		ErrorPages: []store.ErrorPage{{Status: "404"}, {Status: "500-599"}},
	}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, ContentBackend: "http://127.0.0.1:9100", EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(res.Config); err != nil {
		t.Fatalf("validate: %v", err)
	}
	mw := res.Config.HTTP.Middlewares["host-h4-errors"]
	if mw == nil || mw.Errors == nil {
		t.Fatal("expected errors middleware")
	}
	if len(mw.Errors.Status) != 2 || mw.Errors.Service != "xgress-content" {
		t.Errorf("unexpected errors mw: %+v", mw.Errors)
	}
	if !strings.Contains(mw.Errors.Query, h.ID) {
		t.Errorf("error query should be host-scoped: %s", mw.Errors.Query)
	}
	if !contains(res.Config.HTTP.Routers["host-h4"].Middlewares, "host-h4-errors") {
		t.Error("errors middleware not attached to router")
	}
}

func TestRenderErrorPagesNeedsContentBackend(t *testing.T) {
	// No ContentBackend → no errors middleware even if error pages configured.
	h := &store.Host{ID: "h5", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"e.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		ErrorPages: []store.ErrorPage{{Status: "404"}}}
	res, _ := Render(Inputs{Hosts: []*store.Host{h}, EntryPoints: ep()})
	if _, ok := res.Config.HTTP.Middlewares["host-h5-errors"]; ok {
		t.Error("errors middleware must not render without a content backend")
	}
}

// --- mergeConfig / mergeMap (raw passthrough) --------------------------------

func TestMergeRawConfig(t *testing.T) {
	raw := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:     map[string]*dynamic.Router{"extra": {Rule: "PathPrefix(`/extra`)", Service: "extra-svc"}},
			Services:    map[string]*dynamic.Service{"extra-svc": {LoadBalancer: &dynamic.ServersLoadBalancer{Servers: []dynamic.Server{{URL: "http://10.0.0.9"}}}}},
			Middlewares: map[string]*dynamic.Middleware{"extra-mw": {Compress: &dynamic.Compress{}}},
		},
		TLS: &dynamic.TLSConfiguration{Options: map[string]traefiktls.Options{"modern": {MinVersion: "VersionTLS13"}}},
	}
	// A host so the TLS section isn't pruned (cert present) — use an external cert.
	res, err := Render(Inputs{
		EntryPoints:   ep(),
		ExternalCerts: []ExternalCert{{CertPEM: "C", KeyPEM: "K"}},
		RawConfig:     raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Config.HTTP.Routers["extra"]; !ok {
		t.Error("raw router not merged")
	}
	if _, ok := res.Config.HTTP.Services["extra-svc"]; !ok {
		t.Error("raw service not merged")
	}
	if _, ok := res.Config.HTTP.Middlewares["extra-mw"]; !ok {
		t.Error("raw middleware not merged")
	}
	if _, ok := res.Config.TLS.Options["modern"]; !ok {
		t.Error("raw TLS option not merged")
	}
}

func TestMergeRawConfigDstWinsOnCollision(t *testing.T) {
	// A raw router colliding with a xgress-managed router name must NOT override it
	// (xgress config is authoritative).
	h := &store.Host{ID: "keep", Kind: store.HostKindProxy, Enabled: true, Domains: []string{"keep.example.com"},
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone}
	raw := &dynamic.Configuration{HTTP: &dynamic.HTTPConfiguration{
		Routers: map[string]*dynamic.Router{"host-keep": {Rule: "PathPrefix(`/hijack`)", Service: "evil"}},
	}}
	res, err := Render(Inputs{Hosts: []*store.Host{h}, RawConfig: raw, EntryPoints: ep()})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Config.HTTP.Routers["host-keep"].Rule; got != "Host(`keep.example.com`)" {
		t.Errorf("raw config overrode a managed router: rule = %s", got)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

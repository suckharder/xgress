// Package traefikcfg turns xgress's database state into real Traefik configuration.
//
// The render pipeline builds the actual github.com/traefik/traefik/v3 structs —
// not hand-written YAML strings — so anything we produce is type-checked against
// the same code Traefik runs. The rendered dynamic.Configuration is what xgress
// serves to Traefik over the HTTP provider; the static config is generated
// separately in static.go.
package traefikcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	traefiktls "github.com/traefik/traefik/v3/pkg/tls"
	"github.com/traefik/traefik/v3/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

// cacheTokenMW is the shared middleware that injects the edge auth token on
// cache-routed hosts (so the network-exposed cache edge isn't an open proxy).
const cacheTokenMW = "xgress-cache-token"

// EntryPoints names the static HTTP/HTTPS entrypoints the renderer targets.
type EntryPoints struct {
	HTTP  string // e.g. "web"
	HTTPS string // e.g. "websecure"
}

// Inputs is the full database state the renderer consumes. Pulling it once and
// passing it in keeps Render pure and easy to test.
type Inputs struct {
	Hosts        []*store.Host
	Middlewares  []*store.Middleware
	Certificates []*store.Certificate
	AccessLists  []*store.AccessList
	EntryPoints  EntryPoints

	// ChallengeBackend, when set, is the loopback URL of xgress's HTTP-01 challenge
	// responder. The renderer publishes a high-priority router for
	// /.well-known/acme-challenge/ to it so ACME HTTP-01 validation succeeds
	// through Traefik without binding port 80 directly.
	ChallengeBackend string

	// ContentBackend is the loopback base URL of xgress's content responder (default
	// site + custom error pages). When set with DefaultSiteEnabled, a low-priority
	// catch-all router serves unknown hosts from it.
	ContentBackend     string
	DefaultSiteEnabled bool

	// RawConfig is optional, already-validated extra dynamic configuration merged
	// into the rendered output (the "raw passthrough" advanced feature).
	RawConfig *dynamic.Configuration

	// Plugin toggles (Round 2). When enabled, the corresponding plugin middleware
	// is defined and attachable by hosts. The plugin must also be declared in
	// static config (see StaticParams.Plugins).
	WAFEnabled    bool
	WAFDirectives []string

	// CacheEnabled turns on xgress's native server-side cache; CacheBackend is the
	// URL of the cache edge. Cache-enabled hosts route their service to the edge,
	// which caches and reverse-proxies to the real backend. CacheToken, when set, is
	// injected as a request header on cache-routed routers (via the xgress-cache-token
	// middleware) so the edge can reject anything that didn't come through Traefik.
	CacheEnabled bool
	CacheBackend string
	CacheToken   string

	// ExternalCerts are externally-managed certificates (BYO certs) served inline
	// as dynamic TLS material. Each is a PEM cert chain + key.
	ExternalCerts []ExternalCert

	// BannedIPs are source IPs/CIDRs to deny at the edge (fail2ban-style). A
	// highest-priority catch-all matching these client IPs returns 403 via the
	// content responder, across all hosts. Hot-reloaded — no restart.
	BannedIPs []string
}

// ExternalCert is an externally-managed TLS cert/key pair (BYO certs mode).
type ExternalCert struct {
	CertPEM string
	KeyPEM  string
}

// Result is a rendered, hashed dynamic configuration.
type Result struct {
	Config *dynamic.Configuration
	JSON   []byte
	Hash   string
}

// Render builds the complete dynamic configuration from database state.
func Render(in Inputs) (*Result, error) {
	cfg := &dynamic.Configuration{
		HTTP: &dynamic.HTTPConfiguration{
			Routers:     map[string]*dynamic.Router{},
			Services:    map[string]*dynamic.Service{},
			Middlewares: map[string]*dynamic.Middleware{},
		},
		TCP: &dynamic.TCPConfiguration{
			Routers:  map[string]*dynamic.TCPRouter{},
			Services: map[string]*dynamic.TCPService{},
		},
		UDP: &dynamic.UDPConfiguration{
			Routers:  map[string]*dynamic.UDPRouter{},
			Services: map[string]*dynamic.UDPService{},
		},
		TLS: &dynamic.TLSConfiguration{},
	}

	// Always-on ACME HTTP-01 challenge route (high priority, HTTP entrypoint).
	if in.ChallengeBackend != "" {
		cfg.HTTP.Services["acme-http-challenge"] = &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers:        []dynamic.Server{{URL: in.ChallengeBackend}},
				PassHostHeader: ptr.To(true),
			},
		}
		cfg.HTTP.Routers["acme-http-challenge"] = &dynamic.Router{
			Rule:        "PathPrefix(`/.well-known/acme-challenge/`)",
			Service:     "acme-http-challenge",
			EntryPoints: []string{in.EntryPoints.HTTP},
			Priority:    1000000,
		}
	}

	// User-defined reusable middlewares.
	mwByID := map[string]*store.Middleware{}
	for _, m := range in.Middlewares {
		mw, err := BuildMiddleware(m.Type, m.Params)
		if err != nil {
			return nil, fmt.Errorf("middleware %q: %w", m.Name, err)
		}
		cfg.HTTP.Middlewares[mwName(m)] = mw
		mwByID[m.ID] = m
	}

	// Access lists compile to a basicAuth + ipAllowList middleware pair, defined
	// once and referenced by the hosts they're attached to.
	aclByID := map[string]*store.AccessList{}
	for _, a := range in.AccessLists {
		aclByID[a.ID] = a
		if len(a.Users) > 0 {
			users := make([]string, 0, len(a.Users))
			for _, u := range a.Users {
				if u.Username != "" && u.Hash != "" {
					users = append(users, u.Username+":"+u.Hash)
				}
			}
			if len(users) > 0 {
				cfg.HTTP.Middlewares["acl-"+a.ID+"-auth"] = &dynamic.Middleware{
					BasicAuth: &dynamic.BasicAuth{Users: users},
				}
			}
		}
		if len(a.AllowIPs) > 0 {
			cfg.HTTP.Middlewares["acl-"+a.ID+"-ip"] = &dynamic.Middleware{
				IPAllowList: &dynamic.IPAllowList{SourceRange: a.AllowIPs},
			}
		}
	}

	// WAF plugin middleware (defined once; hosts attach it via the toggle).
	if in.WAFEnabled {
		cfg.HTTP.Middlewares["xgress-waf"] = wafMiddleware(in.WAFDirectives)
	}

	// Cache-edge auth middleware (defined once; cache-routed hosts attach it). It adds
	// the token header so only Traefik can reach the network-exposed edge.
	if in.CacheEnabled && in.CacheBackend != "" && in.CacheToken != "" {
		cfg.HTTP.Middlewares[cacheTokenMW] = &dynamic.Middleware{
			Headers: &dynamic.Headers{CustomRequestHeaders: map[string]string{config.EdgeTokenHeader: in.CacheToken}},
		}
	}

	// Shared content service (default site + custom error pages) → xgress responder.
	if in.ContentBackend != "" {
		cfg.HTTP.Services["xgress-content"] = &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers:        []dynamic.Server{{URL: in.ContentBackend}},
				PassHostHeader: ptr.To(false),
			},
		}
	}

	// Externally-managed (BYO) certificates served inline. Keys are present in the
	// served document (they come from a trusted mounted volume, not the DB), so no
	// @@KEY placeholder is used.
	for _, ec := range in.ExternalCerts {
		if ec.CertPEM == "" || ec.KeyPEM == "" {
			continue
		}
		cfg.TLS.Certificates = append(cfg.TLS.Certificates, &traefiktls.CertAndStores{
			Certificate: traefiktls.Certificate{
				CertFile: types.FileOrContent(ec.CertPEM),
				KeyFile:  types.FileOrContent(ec.KeyPEM),
			},
		})
	}

	// Certificates that are valid get served inline as dynamic TLS certificates.
	certByID := map[string]*store.Certificate{}
	for _, c := range in.Certificates {
		certByID[c.ID] = c
		if c.Status == store.CertStatusValid && c.CertPEM != "" {
			cfg.TLS.Certificates = append(cfg.TLS.Certificates, &traefiktls.CertAndStores{
				Certificate: traefiktls.Certificate{
					CertFile: types.FileOrContent(c.CertPEM),
					// KeyPEM is injected by the caller after decryption; see WithDecryptedKeys.
					KeyFile: types.FileOrContent("@@KEY:" + c.ID),
				},
			})
		}
	}

	for _, h := range in.Hosts {
		if !h.Enabled {
			continue
		}
		switch h.Kind {
		case store.HostKindProxy:
			renderProxyHost(cfg, h, mwByID, aclByID, in)
		case store.HostKindRedirection:
			renderRedirectionHost(cfg, h, mwByID, in.EntryPoints)
		case store.HostKindStream:
			renderStreamHost(cfg, h)
		case store.HostKindDead:
			// handled as a low-priority catch-all; see renderDeadHost
			renderDeadHost(cfg, h, in.EntryPoints)
		}
	}

	// Default Site: a low-priority catch-all for unknown hosts, routed to xgress's
	// content responder (which serves 404 / redirect / custom / welcome / close
	// based on settings — read live, so no Traefik restart to change behavior).
	if in.DefaultSiteEnabled && in.ContentBackend != "" {
		cfg.HTTP.Middlewares["xgress-default-path"] = &dynamic.Middleware{
			ReplacePath: &dynamic.ReplacePath{Path: "/__xgress/default"},
		}
		// Lowest-priority catch-all (any path, any host). Real host routers have
		// higher priority (longer rules), so they always win. Split per entrypoint
		// because the websecure variant must require TLS.
		cfg.HTTP.Routers["xgress-default-site-http"] = &dynamic.Router{
			Rule:        "PathPrefix(`/`)",
			Service:     "xgress-content",
			EntryPoints: []string{in.EntryPoints.HTTP},
			Middlewares: []string{"xgress-default-path"},
			Priority:    1,
		}
		cfg.HTTP.Routers["xgress-default-site-https"] = &dynamic.Router{
			Rule:        "PathPrefix(`/`)",
			Service:     "xgress-content",
			EntryPoints: []string{in.EntryPoints.HTTPS},
			Middlewares: []string{"xgress-default-path"},
			Priority:    1,
			TLS:         &dynamic.RouterTLSConfig{},
		}
	}

	// Banned IPs: a highest-priority deny across all hosts (fail2ban-style). Emit a
	// SINGLE ClientIP(`a`, `b`, …) matcher (Traefik accepts multiple comma-separated
	// values) rather than an `a || b || …` OR-chain of separate matcher nodes — this
	// router is evaluated first on every request, so one set-membership matcher is
	// much cheaper than N OR'd nodes.
	if len(in.BannedIPs) > 0 && in.ContentBackend != "" {
		quoted := make([]string, 0, len(in.BannedIPs))
		for _, ip := range in.BannedIPs {
			quoted = append(quoted, fmt.Sprintf("`%s`", ruleQuote(ip)))
		}
		ipRule := fmt.Sprintf("ClientIP(%s)", strings.Join(quoted, ", "))
		cfg.HTTP.Middlewares["xgress-banned-path"] = &dynamic.Middleware{
			ReplacePath: &dynamic.ReplacePath{Path: "/__xgress/banned"},
		}
		cfg.HTTP.Routers["xgress-banned-http"] = &dynamic.Router{
			Rule:        fmt.Sprintf("(%s) && PathPrefix(`/`)", ipRule),
			Service:     "xgress-content",
			EntryPoints: []string{in.EntryPoints.HTTP},
			Middlewares: []string{"xgress-banned-path"},
			Priority:    2000000,
		}
		cfg.HTTP.Routers["xgress-banned-https"] = &dynamic.Router{
			Rule:        fmt.Sprintf("(%s) && PathPrefix(`/`)", ipRule),
			Service:     "xgress-content",
			EntryPoints: []string{in.EntryPoints.HTTPS},
			Middlewares: []string{"xgress-banned-path"},
			Priority:    2000000,
			TLS:         &dynamic.RouterTLSConfig{},
		}
	}

	// Raw passthrough: merge already-validated extra dynamic config.
	if in.RawConfig != nil {
		mergeConfig(cfg, in.RawConfig)
	}

	// Traefik's provider decoder rejects empty "standalone" sections (e.g. an
	// empty tcp: {} — or an empty http: {}). Drop any section we did not populate so
	// the served document only contains what is actually configured. HTTP is usually
	// non-empty in production (the ACME-challenge / default-site routers), but a
	// stream-only config — only TCP/UDP hosts, no HTTP — would otherwise emit an
	// empty HTTP section and Traefik would reject the whole document.
	if len(cfg.HTTP.Routers) == 0 && len(cfg.HTTP.Services) == 0 && len(cfg.HTTP.Middlewares) == 0 {
		cfg.HTTP = nil
	}
	if len(cfg.TCP.Routers) == 0 && len(cfg.TCP.Services) == 0 {
		cfg.TCP = nil
	}
	if len(cfg.UDP.Routers) == 0 && len(cfg.UDP.Services) == 0 {
		cfg.UDP = nil
	}
	if len(cfg.TLS.Certificates) == 0 && len(cfg.TLS.Options) == 0 && len(cfg.TLS.Stores) == 0 {
		cfg.TLS = nil
	}

	// Stable JSON for hashing/serving (map ordering is normalised by json).
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &Result{Config: cfg, JSON: raw, Hash: hex.EncodeToString(sum[:])}, nil
}

// buildServersLB builds a ServersLoadBalancer from upstreams + strategy/sticky/
// health settings, reused by the main host service and per-location services.
func buildServersLB(h *store.Host, upstreams []store.Upstream) *dynamic.ServersLoadBalancer {
	servers := make([]dynamic.Server, 0, len(upstreams))
	for _, u := range upstreams {
		scheme := u.Scheme
		if scheme == "" {
			scheme = "http"
		}
		url := fmt.Sprintf("%s://%s", scheme, u.Host)
		if u.Port != 0 {
			url = fmt.Sprintf("%s://%s:%d", scheme, u.Host, u.Port)
		}
		s := dynamic.Server{URL: url}
		if u.Weight > 0 {
			s.Weight = ptr.To(u.Weight)
		}
		servers = append(servers, s)
	}
	lb := &dynamic.ServersLoadBalancer{Servers: servers, PassHostHeader: ptr.To(true)}
	switch h.LoadBalancer {
	case "p2c":
		lb.Strategy = dynamic.BalancerStrategyP2C
	case "leasttime":
		lb.Strategy = dynamic.BalancerStrategyLeastTime
	}
	if h.HealthCheckURL != "" {
		lb.HealthCheck = &dynamic.ServerHealthCheck{Path: h.HealthCheckURL}
	}
	if h.Sticky {
		lb.Sticky = &dynamic.Sticky{Cookie: &dynamic.Cookie{
			Name: "xgress_lb", HTTPOnly: true, Secure: h.TLS != store.TLSNone, SameSite: "lax",
		}}
	}
	return lb
}

// buildHostService registers the host's service(s) under svc-<id>. In single
// mode it's one ServersLoadBalancer; the composition modes (weighted/canary,
// failover, mirroring) build a leaf service per backend group plus a composed
// service that references them.
func buildHostService(cfg *dynamic.Configuration, h *store.Host, cacheEnabled bool, cacheBackend string) {
	svcName := "svc-" + h.ID
	// Cache-enabled hosts route to xgress's cache edge, which caches GET responses
	// and reverse-proxies to the real backend (which it resolves itself).
	if h.Cache && cacheEnabled && cacheBackend != "" {
		cfg.HTTP.Services[svcName] = &dynamic.Service{LoadBalancer: &dynamic.ServersLoadBalancer{
			Servers:        []dynamic.Server{{URL: cacheBackend}},
			PassHostHeader: ptr.To(true),
		}}
		return
	}
	mode := h.ServiceMode
	if mode == "" || mode == "single" || len(h.BackendGroups) == 0 {
		cfg.HTTP.Services[svcName] = &dynamic.Service{LoadBalancer: buildServersLB(h, h.Upstreams)}
		return
	}

	groupSvc := make([]string, len(h.BackendGroups))
	for i, g := range h.BackendGroups {
		name := fmt.Sprintf("svc-%s-g%d", h.ID, i)
		groupSvc[i] = name
		cfg.HTTP.Services[name] = &dynamic.Service{LoadBalancer: buildServersLB(h, g.Upstreams)}
	}

	switch mode {
	case "weighted":
		wrr := &dynamic.WeightedRoundRobin{}
		for i, g := range h.BackendGroups {
			w := g.Weight
			if w <= 0 {
				w = 1
			}
			wrr.Services = append(wrr.Services, dynamic.WRRService{Name: groupSvc[i], Weight: ptr.To(w)})
		}
		if h.Sticky {
			wrr.Sticky = &dynamic.Sticky{Cookie: &dynamic.Cookie{
				Name: "xgress_canary", HTTPOnly: true, Secure: h.TLS != store.TLSNone, SameSite: "lax",
			}}
		}
		cfg.HTTP.Services[svcName] = &dynamic.Service{Weighted: wrr}
	case "failover":
		fo := &dynamic.Failover{Service: groupSvc[0]}
		if len(groupSvc) > 1 {
			fo.Fallback = groupSvc[1]
		}
		cfg.HTTP.Services[svcName] = &dynamic.Service{Failover: fo}
	case "mirroring":
		mir := &dynamic.Mirroring{Service: groupSvc[0]}
		for i := 1; i < len(h.BackendGroups); i++ {
			mir.Mirrors = append(mir.Mirrors, dynamic.MirrorService{Name: groupSvc[i], Percent: h.BackendGroups[i].Percent})
		}
		cfg.HTTP.Services[svcName] = &dynamic.Service{Mirroring: mir}
	default:
		cfg.HTTP.Services[svcName] = &dynamic.Service{LoadBalancer: buildServersLB(h, h.Upstreams)}
	}
}

// renderProxyHost maps a proxy host to a router + service (+ generated mw,
// access lists, error pages, and path-scoped locations).
func renderProxyHost(cfg *dynamic.Configuration, h *store.Host, mwByID map[string]*store.Middleware, aclByID map[string]*store.AccessList, in Inputs) {
	ep := in.EntryPoints
	svcName := "svc-" + h.ID
	routerName := "host-" + h.ID

	buildHostService(cfg, h, in.CacheEnabled, in.CacheBackend)

	// Middleware chain: WAF (security gate) first, then access lists (auth/IP),
	// then per-host generated (HSTS), error pages, user middlewares, then cache.
	var mws []string
	if h.WAF && in.WAFEnabled {
		mws = append(mws, "xgress-waf")
	}
	mws = append(mws, accessListMiddlewares(h, aclByID)...)
	mws = append(mws, collectMiddlewareNames(cfg, h, mwByID)...)
	if epName := errorPagesMiddleware(cfg, h, in.ContentBackend); epName != "" {
		mws = append(mws, epName)
	}
	mws = append(mws, perHostRawMiddlewares(cfg, h)...)

	// Cache-routed hosts go through the edge, which is token-gated when network-exposed.
	// Inject the token middleware on routers that target the edge (main, static-asset,
	// satisfy-any bypass) — but NOT location routers, which have their own non-edge
	// services (so locMwsBase, the pre-token chain, is used for those).
	locMwsBase := mws
	if h.Cache && in.CacheEnabled && in.CacheBackend != "" && in.CacheToken != "" {
		mws = append(append([]string{}, mws...), cacheTokenMW)
	}

	tlsEnabled := h.TLS == store.TLSACME || h.TLS == store.TLSCustom || h.TLS == store.TLSExternal
	entryPoint := ep.HTTP
	if tlsEnabled {
		entryPoint = ep.HTTPS
	}

	router := &dynamic.Router{
		Rule:        hostRule(h.Domains),
		Service:     svcName,
		EntryPoints: []string{entryPoint},
		Middlewares: mws,
	}
	if tlsEnabled {
		router.TLS = &dynamic.RouterTLSConfig{}
	}
	cfg.HTTP.Routers[routerName] = router

	// Satisfy-any access lists: requests from a trusted IP range skip auth. We add
	// a higher-priority router matching the host rule AND ClientIP(trusted ranges)
	// that drops the auth (and redundant IP) middlewares; others fall through to
	// the normal router which still requires auth.
	addSatisfyAnyBypass(cfg, h, aclByID, mws, svcName, entryPoint, tlsEnabled)

	// Client-side caching: a higher-priority router matching common static-asset
	// extensions adds a long Cache-Control header to those responses (the rest of
	// the site is unaffected). Mirrors NPM's "Cache Assets".
	if h.CacheAssets {
		cacheMw := "host-" + h.ID + "-cache"
		cfg.HTTP.Middlewares[cacheMw] = &dynamic.Middleware{
			Headers: &dynamic.Headers{
				CustomResponseHeaders: map[string]string{"Cache-Control": "public, max-age=2592000"},
			},
		}
		sr := &dynamic.Router{
			Rule:        fmt.Sprintf("(%s) && PathRegexp(`%s`)", hostRule(h.Domains), staticAssetRegex),
			Service:     svcName,
			EntryPoints: []string{entryPoint},
			Middlewares: append(append([]string{}, mws...), cacheMw),
			Priority:    900,
		}
		if tlsEnabled {
			sr.TLS = &dynamic.RouterTLSConfig{}
		}
		cfg.HTTP.Routers["host-"+h.ID+"-static"] = sr
	}

	// Path-scoped locations: each gets a higher-priority router (host rule +
	// PathPrefix) and its own service.
	for i, loc := range h.Locations {
		if loc.PathPrefix == "" || len(loc.Upstreams) == 0 {
			continue
		}
		locSvc := fmt.Sprintf("svc-%s-loc%d", h.ID, i)
		cfg.HTTP.Services[locSvc] = &dynamic.Service{LoadBalancer: buildServersLB(h, loc.Upstreams)}
		locMws := append([]string{}, locMwsBase...)
		if loc.StripPrefix {
			sp := fmt.Sprintf("host-%s-loc%d-strip", h.ID, i)
			cfg.HTTP.Middlewares[sp] = &dynamic.Middleware{StripPrefix: &dynamic.StripPrefix{Prefixes: []string{loc.PathPrefix}}}
			locMws = append(locMws, sp)
		}
		lr := &dynamic.Router{
			Rule:        fmt.Sprintf("(%s) && PathPrefix(`%s`)", hostRule(h.Domains), ruleQuote(loc.PathPrefix)),
			Service:     locSvc,
			EntryPoints: []string{entryPoint},
			Middlewares: locMws,
			Priority:    1000 + len(loc.PathPrefix),
		}
		if tlsEnabled {
			lr.TLS = &dynamic.RouterTLSConfig{}
		}
		cfg.HTTP.Routers[fmt.Sprintf("host-%s-loc%d", h.ID, i)] = lr
	}

	// HTTP->HTTPS redirect router on the HTTP entrypoint.
	if tlsEnabled && h.ForceTLS {
		redirName := routerName + "-redirect-mw"
		cfg.HTTP.Middlewares[redirName] = &dynamic.Middleware{
			RedirectScheme: &dynamic.RedirectScheme{Scheme: "https", Permanent: true},
		}
		cfg.HTTP.Routers[routerName+"-http"] = &dynamic.Router{
			Rule:        hostRule(h.Domains),
			Service:     svcName,
			EntryPoints: []string{ep.HTTP},
			Middlewares: []string{redirName},
		}
	}
}

// perHostRawMiddlewares parses a host's optional raw YAML (Round 4b), namespaces
// everything it defines as host-<id>-raw-<name>, and merges it. Middlewares are
// returned so they can be attached to the host's main router; routers and
// services are merged standalone with intra-fragment references rewritten to the
// namespaced names (so a raw router referencing a raw service/middleware keeps
// working). Parse errors are skipped (the API validates raw YAML on save).
func perHostRawMiddlewares(cfg *dynamic.Configuration, h *store.Host) []string {
	if strings.TrimSpace(h.RawYAML) == "" {
		return nil
	}
	frag, err := ParseRawConfig(h.RawYAML)
	if err != nil || frag == nil || frag.HTTP == nil {
		return nil
	}
	ns := func(name string) string { return "host-" + h.ID + "-raw-" + name }

	// Per-host raw supports middlewares (+ the services they reference) only — NOT
	// routers. Operator-authored routers could shadow xgress's system routers (the
	// ban/ACME deny) or capture another host's domains, so router injection is
	// reserved for the admin-only global raw config. Any routers in the fragment
	// are ignored here and rejected at save time (validateHost → rawYAMLIssues).
	for name, svc := range frag.HTTP.Services {
		cfg.HTTP.Services[ns(name)] = svc
	}
	var attach []string
	for name, mw := range frag.HTTP.Middlewares {
		cfg.HTTP.Middlewares[ns(name)] = mw
		attach = append(attach, ns(name))
	}
	sort.Strings(attach)
	return attach
}

// addSatisfyAnyBypass implements "satisfy any" for access lists: a higher-priority
// router that lets trusted source IPs through without basic auth.
func addSatisfyAnyBypass(cfg *dynamic.Configuration, h *store.Host, aclByID map[string]*store.AccessList, mws []string, svcName, entryPoint string, tlsEnabled bool) {
	var bypassIPs []string
	drop := map[string]bool{}
	for _, id := range h.AccessListIDs {
		a, ok := aclByID[id]
		if !ok || !a.SatisfyAny || len(a.AllowIPs) == 0 || len(a.Users) == 0 {
			continue
		}
		bypassIPs = append(bypassIPs, a.AllowIPs...)
		drop["acl-"+a.ID+"-auth"] = true // skip auth for trusted IPs
		drop["acl-"+a.ID+"-ip"] = true   // ClientIP match already restricts to these
	}
	if len(bypassIPs) == 0 {
		return
	}
	var ipParts []string
	for _, ip := range bypassIPs {
		ipParts = append(ipParts, fmt.Sprintf("ClientIP(`%s`)", ruleQuote(ip)))
	}
	var keep []string
	for _, m := range mws {
		if !drop[m] {
			keep = append(keep, m)
		}
	}
	r := &dynamic.Router{
		Rule:        fmt.Sprintf("(%s) && (%s)", hostRule(h.Domains), strings.Join(ipParts, " || ")),
		Service:     svcName,
		EntryPoints: []string{entryPoint},
		Middlewares: keep,
		Priority:    2000,
	}
	if tlsEnabled {
		r.TLS = &dynamic.RouterTLSConfig{}
	}
	cfg.HTTP.Routers["host-"+h.ID+"-trusted"] = r
}

// accessListMiddlewares returns the middleware names for the access lists
// attached to a host (basicAuth + ipAllowList, defined once in Render).
func accessListMiddlewares(h *store.Host, aclByID map[string]*store.AccessList) []string {
	var out []string
	for _, id := range h.AccessListIDs {
		a, ok := aclByID[id]
		if !ok {
			continue
		}
		if len(a.AllowIPs) > 0 {
			out = append(out, "acl-"+a.ID+"-ip")
		}
		if len(a.Users) > 0 {
			out = append(out, "acl-"+a.ID+"-auth")
		}
	}
	return out
}

// errorPagesMiddleware defines an `errors` middleware for a host's custom error
// pages and returns its name (or "" if none). It serves content from xgress's
// content responder via the shared xgress-content service.
func errorPagesMiddleware(cfg *dynamic.Configuration, h *store.Host, contentBackend string) string {
	if len(h.ErrorPages) == 0 || contentBackend == "" {
		return ""
	}
	var statuses []string
	for _, ep := range h.ErrorPages {
		if ep.Status != "" {
			statuses = append(statuses, ep.Status)
		}
	}
	if len(statuses) == 0 {
		return ""
	}
	name := "host-" + h.ID + "-errors"
	cfg.HTTP.Middlewares[name] = &dynamic.Middleware{
		Errors: &dynamic.ErrorPage{
			Status:  statuses,
			Service: "xgress-content",
			Query:   "/__xgress/error/" + h.ID + "/{status}",
		},
	}
	return name
}

// mergeConfig merges src's HTTP/TCP/UDP/TLS maps into dst (raw passthrough).
// dst's entries win on key collision (xgress-managed config is authoritative).
func mergeConfig(dst, src *dynamic.Configuration) {
	if src.HTTP != nil {
		mergeMap(dst.HTTP.Routers, src.HTTP.Routers)
		mergeMap(dst.HTTP.Services, src.HTTP.Services)
		mergeMap(dst.HTTP.Middlewares, src.HTTP.Middlewares)
	}
	if src.TCP != nil && dst.TCP != nil {
		mergeMap(dst.TCP.Routers, src.TCP.Routers)
		mergeMap(dst.TCP.Services, src.TCP.Services)
	}
	if src.TLS != nil && dst.TLS != nil && len(src.TLS.Options) > 0 {
		if dst.TLS.Options == nil {
			dst.TLS.Options = map[string]traefiktls.Options{}
		}
		for k, v := range src.TLS.Options {
			if _, exists := dst.TLS.Options[k]; !exists {
				dst.TLS.Options[k] = v
			}
		}
	}
}

func mergeMap[T any](dst, src map[string]T) {
	for k, v := range src {
		if _, exists := dst[k]; !exists {
			dst[k] = v
		}
	}
}

func renderRedirectionHost(cfg *dynamic.Configuration, h *store.Host, mwByID map[string]*store.Middleware, ep EntryPoints) {
	code := h.RedirectCode
	if code == 0 {
		code = 308
	}
	// A redirectRegex middleware rewrites any path to the target.
	mwName := "host-" + h.ID + "-redirect"
	replacement := h.RedirectTo
	regex := "^https?://[^/]+(.*)"
	if h.RedirectKeepPath {
		replacement = strings.TrimRight(h.RedirectTo, "/") + "${1}"
	}
	cfg.HTTP.Middlewares[mwName] = &dynamic.Middleware{
		RedirectRegex: &dynamic.RedirectRegex{Regex: regex, Replacement: replacement, Permanent: code == 301 || code == 308},
	}
	// A tiny service is still required for a router; reuse a noop service.
	noop := "noop"
	if _, ok := cfg.HTTP.Services[noop]; !ok {
		cfg.HTTP.Services[noop] = &dynamic.Service{LoadBalancer: &dynamic.ServersLoadBalancer{
			Servers: []dynamic.Server{{URL: "http://127.0.0.1:1"}},
		}}
	}
	mws := append([]string{mwName}, collectMiddlewareNames(cfg, h, mwByID)...)
	tlsEnabled := h.TLS != store.TLSNone
	entryPoint := ep.HTTP
	if tlsEnabled {
		entryPoint = ep.HTTPS
	}
	r := &dynamic.Router{Rule: hostRule(h.Domains), Service: noop, EntryPoints: []string{entryPoint}, Middlewares: mws}
	if tlsEnabled {
		r.TLS = &dynamic.RouterTLSConfig{}
	}
	cfg.HTTP.Routers["host-"+h.ID] = r
}

func renderDeadHost(cfg *dynamic.Configuration, h *store.Host, ep EntryPoints) {
	// Catch-all low priority router returning 404 via an errors-style noop.
	noop := "noop"
	if _, ok := cfg.HTTP.Services[noop]; !ok {
		cfg.HTTP.Services[noop] = &dynamic.Service{LoadBalancer: &dynamic.ServersLoadBalancer{
			Servers: []dynamic.Server{{URL: "http://127.0.0.1:1"}},
		}}
	}
	cfg.HTTP.Routers["host-"+h.ID] = &dynamic.Router{
		Rule:        hostRule(h.Domains),
		Service:     noop,
		EntryPoints: []string{ep.HTTP, ep.HTTPS},
		Priority:    1,
	}
}

func renderStreamHost(cfg *dynamic.Configuration, h *store.Host) {
	if len(h.Upstreams) == 0 || h.StreamEntryPoint == "" {
		return
	}
	addr := fmt.Sprintf("%s:%d", h.Upstreams[0].Host, h.Upstreams[0].Port)
	switch strings.ToLower(h.StreamProto) {
	case "udp":
		cfg.UDP.Services["svc-"+h.ID] = &dynamic.UDPService{
			LoadBalancer: &dynamic.UDPServersLoadBalancer{Servers: []dynamic.UDPServer{{Address: addr}}},
		}
		cfg.UDP.Routers["host-"+h.ID] = &dynamic.UDPRouter{
			EntryPoints: []string{h.StreamEntryPoint},
			Service:     "svc-" + h.ID,
		}
	default: // tcp
		cfg.TCP.Services["svc-"+h.ID] = &dynamic.TCPService{
			LoadBalancer: &dynamic.TCPServersLoadBalancer{Servers: []dynamic.TCPServer{{Address: addr}}},
		}
		rule := "HostSNI(`*`)"
		if len(h.Domains) > 0 {
			parts := make([]string, len(h.Domains))
			for i, d := range h.Domains {
				parts[i] = fmt.Sprintf("HostSNI(`%s`)", ruleQuote(d))
			}
			rule = strings.Join(parts, " || ")
		}
		r := &dynamic.TCPRouter{
			EntryPoints: []string{h.StreamEntryPoint},
			Service:     "svc-" + h.ID,
			Rule:        rule,
		}
		// TLS passthrough: route by SNI and forward the raw encrypted stream to a
		// backend that terminates TLS itself. HostSNI(`*`) is not allowed with
		// passthrough, so it requires explicit SNI domains.
		if h.TLSPassthrough && len(h.Domains) > 0 {
			r.TLS = &dynamic.RouterTCPTLSConfig{Passthrough: true}
		}
		cfg.TCP.Routers["host-"+h.ID] = r
	}
}

// collectMiddlewareNames adds generated per-host middlewares (HSTS) and returns
// the ordered list of middleware names attached to the host's router.
func collectMiddlewareNames(cfg *dynamic.Configuration, h *store.Host, mwByID map[string]*store.Middleware) []string {
	var names []string
	if h.HSTS {
		hstsName := "host-" + h.ID + "-hsts"
		cfg.HTTP.Middlewares[hstsName] = &dynamic.Middleware{
			Headers: &dynamic.Headers{
				STSSeconds:           ptr.To(int64(31536000)),
				STSIncludeSubdomains: true,
				STSPreload:           true,
			},
		}
		names = append(names, hstsName)
	}
	// CORS: a generated headers middleware allowing the configured origins. Traefik's
	// headers middleware answers preflight (OPTIONS) automatically once an origin
	// list is set; methods/allowed-headers use sensible defaults. AddVaryHeader keeps
	// shared caches (incl. xgress's edge) correct per Origin.
	if h.CORSEnabled && len(h.CORSAllowOrigins) > 0 {
		corsName := "host-" + h.ID + "-cors"
		cfg.HTTP.Middlewares[corsName] = &dynamic.Middleware{
			Headers: &dynamic.Headers{
				AccessControlAllowOriginList:  h.CORSAllowOrigins,
				AccessControlAllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
				AccessControlAllowHeaders:     []string{"Origin", "Accept", "Content-Type", "Authorization", "X-Requested-With"},
				AccessControlAllowCredentials: h.CORSAllowCredentials,
				AccessControlMaxAge:           600,
				AddVaryHeader:                 true,
			},
		}
		names = append(names, corsName)
	}
	for _, id := range h.MiddlewareIDs {
		if m, ok := mwByID[id]; ok {
			names = append(names, mwName(m))
		}
	}
	return names
}

func mwName(m *store.Middleware) string { return "mw-" + m.ID }

// staticAssetRegex matches common static-asset file extensions at the end of the
// request path (used by the client-side cache feature).
const staticAssetRegex = `\.(?:js|mjs|css|png|jpe?g|gif|ico|svg|webp|avif|woff2?|ttf|eot|otf|mp4|webm|map)$`

// ruleQuote sanitizes a value before it is interpolated into a backtick-delimited
// Traefik rule matcher (Host(`…`), HostSNI(`…`), PathPrefix(`…`), ClientIP(`…`)).
// Traefik's rule syntax has no escape for an embedded backtick, so a stray backtick
// would otherwise close the matcher and inject arbitrary rule syntax. These values
// are validated at save time; this is the defense-in-depth net that guarantees the
// *served* config can never contain an injected matcher, regardless of how a row was
// created (legacy data, restore, direct DB write). Stripping the backtick is
// sufficient — every other character stays a harmless literal inside the matcher.
func ruleQuote(s string) string {
	if !strings.ContainsRune(s, '`') {
		return s
	}
	return strings.ReplaceAll(s, "`", "")
}

// hostRule builds a Traefik v3 Host(...) rule from one or more domains.
func hostRule(domains []string) string {
	if len(domains) == 0 {
		return "PathPrefix(`/`)"
	}
	parts := make([]string, len(domains))
	for i, d := range domains {
		parts[i] = fmt.Sprintf("Host(`%s`)", ruleQuote(d))
	}
	sort.Strings(parts)
	return strings.Join(parts, " || ")
}

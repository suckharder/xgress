// Package engine is the orchestration core that connects the database to the
// running proxy. It owns the render→validate→snapshot→serve pipeline, decides
// when a Traefik restart is genuinely required (only static-config changes), and
// drives certificate issuance/renewal. The REST API calls into the engine; the
// engine never imports the API.
package engine

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/edge"
	"github.com/suckharder/xgress/internal/notify"
	"github.com/suckharder/xgress/internal/secmetrics"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
	"github.com/suckharder/xgress/internal/traefikapi"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

// Engine wires together every subsystem behind a small mutating API.
type Engine struct {
	cfg  *config.Config
	st   *store.Store
	box  *secrets.Box
	sup  *supervisor.Supervisor
	acme *acme.Manager
	log  *slog.Logger

	challengeBackend string
	holderID         string // identifies this instance for leader-election leases
	edge             *edge.Server
	cacheBackend     string
	cacheToken       string // edge auth token injected on cache-routed hosts
	tapi             *traefikapi.Client
	notifier         *notify.Dispatcher
	secmetrics       *secmetrics.Collector

	mu       sync.RWMutex
	rendered *traefikcfg.Result // last successfully rendered+validated config
	version  int64

	banMu     sync.Mutex
	banHits   map[string][]time.Time // client IP -> sliding window of WAF block timestamps
	banReload chan struct{}          // coalesces auto-ban reloads (debounced in banReloadLoop)
}

// New constructs an Engine.
func New(cfg *config.Config, st *store.Store, box *secrets.Box, sup *supervisor.Supervisor, am *acme.Manager, challengeBackend string, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	host, _ := os.Hostname()
	e := &Engine{cfg: cfg, st: st, box: box, sup: sup, acme: am, challengeBackend: challengeBackend,
		holderID: fmt.Sprintf("%s-%d", host, os.Getpid()), log: log,
		banHits: map[string][]time.Time{}, banReload: make(chan struct{}, 1)}
	e.tapi = traefikapi.New(cfg.TraefikAPIListen)
	e.notifier = notify.New(e.notifyConfig, log)
	e.secmetrics = secmetrics.New()
	// Feed captured Traefik logs (incl. Coraza WAF output) to the collector. The
	// supervisor extracts the unescaped inner message — Coraza blocks arrive as a
	// Traefik error line whose message is the ModSecurity-style `[id "…"] …`.
	sup.AddLogObserver(func(ll supervisor.LogLine) { e.secmetrics.Ingest(ll.Message, ll.At) })
	// Auto-ban: evaluate each WAF block against the sliding-window threshold.
	e.secmetrics.AddObserver(e.onWAFEvent)
	return e
}

// SetHolderID overrides the leader-election holder identity. It is auto-derived
// from hostname+PID in New, which is unique across hosts and across containers; the
// override exists for tests that run multiple engines in one process (same PID) and
// for operators who want a stable, explicit instance identity.
func (e *Engine) SetHolderID(id string) { e.holderID = id }

// SecurityMetrics returns the current WAF security-metrics snapshot.
func (e *Engine) SecurityMetrics() secmetrics.Snapshot { return e.secmetrics.Snapshot() }

// WAFEnabled reports whether the WAF plugin is loaded.
func (e *Engine) WAFEnabled(ctx context.Context) bool { return e.wafEnabled(ctx) }

// SetCacheEdge wires the native cache edge, the backend URL Traefik routes cached
// hosts to, and the token the renderer injects so only Traefik can reach the edge.
func (e *Engine) SetCacheEdge(s *edge.Server, backend, token string) {
	e.edge = s
	e.cacheBackend = backend
	e.cacheToken = token
}

// CacheBackendName reports the cache storage backend ("redis" or "in-memory"),
// or "" if the cache edge is not wired.
func (e *Engine) CacheBackendName() string {
	if e.edge == nil {
		return ""
	}
	return e.edge.CacheName()
}

// TraefikAPI exposes the read-only Traefik API client (metrics, discovery).
func (e *Engine) TraefikAPI() *traefikapi.Client { return e.tapi }

// Notifier exposes the alert dispatcher (used by the API for the "test" action).
func (e *Engine) Notifier() *notify.Dispatcher { return e.notifier }

// notifyConfig resolves the current notification settings from the store,
// decrypting the SMTP password.
func (e *Engine) notifyConfig(ctx context.Context) notify.Config {
	g := func(k string) string { v, _ := e.st.GetSetting(ctx, k); return v }
	pass := ""
	if enc := g("notify.smtpPassEnc"); enc != "" {
		if p, err := e.box.DecryptString(enc); err != nil {
			e.log.Error("notify: SMTP password failed to decrypt; sending without auth", "err", err)
		} else {
			pass = p
		}
	}
	return notify.Config{
		WebhookURL: g("notify.webhookUrl"),
		EmailTo:    g("notify.email"),
		SMTPHost:   g("notify.smtpHost"),
		SMTPPort:   g("notify.smtpPort"),
		SMTPUser:   g("notify.smtpUser"),
		SMTPPass:   pass,
		SMTPFrom:   g("notify.smtpFrom"),
	}
}

// Supervisor exposes the supervised Traefik process (status/logs/restart).
func (e *Engine) Supervisor() *supervisor.Supervisor { return e.sup }

// ACME exposes the certificate manager.
func (e *Engine) ACME() *acme.Manager { return e.acme }

// Bootstrap renders the initial dynamic config, writes the static config, and
// starts Traefik. Called once at startup.
func (e *Engine) Bootstrap(ctx context.Context) error {
	if _, err := e.Reload(ctx); err != nil {
		// Even if the user's config is somehow invalid, continue: Traefik will
		// run with an empty-but-valid config and the UI surfaces the error.
		e.log.Error("initial reload failed", "err", err)
	}
	if err := e.SyncStatic(ctx, false); err != nil {
		return fmt.Errorf("write static config: %w", err)
	}
	if err := e.sup.Start(ctx); err != nil {
		return fmt.Errorf("start traefik: %w", err)
	}
	return nil
}

// Reload pulls current state from the database, renders + validates a new
// dynamic configuration, snapshots it as last-known-good, and atomically swaps
// it into the served cache. On any error the previously served config is kept,
// so a bad change never takes down the proxy.
func (e *Engine) Reload(ctx context.Context) (*traefikcfg.Result, error) {
	res, hosts, err := e.renderConfig(ctx)
	if err != nil {
		return nil, err
	}

	// Keep the cache edge's domain→host index in sync with what we serve.
	if e.edge != nil {
		e.edge.SetHosts(hosts)
	}

	// Persist snapshot as last-known-good and bump version.
	next, err := e.st.LatestSnapshotVersion(ctx)
	if err != nil {
		return nil, err
	}
	next++
	snap := &store.ConfigSnapshot{Version: next, JSON: string(res.JSON), Hash: res.Hash, Valid: true}
	if err := e.st.AddSnapshot(ctx, snap); err != nil {
		return nil, err
	}
	_ = e.st.PruneSnapshots(ctx, 50)

	e.mu.Lock()
	e.rendered = res
	e.version = next
	e.mu.Unlock()
	e.log.Info("dynamic config reloaded", "version", next, "hash", res.Hash[:12])
	return res, nil
}

// Preview renders + validates the current database state WITHOUT any side effects
// (no snapshot, no version bump, no serve swap, no cache-edge update). It backs
// GET /api/config/preview so a read-only viewer — or a CSRF'd request — cannot
// mutate served state just by previewing.
func (e *Engine) Preview(ctx context.Context) (*traefikcfg.Result, error) {
	res, _, err := e.renderConfig(ctx)
	return res, err
}

// renderConfig pulls current state from the DB and produces a validated dynamic
// configuration. Pure: no snapshot, version bump, serve swap, or cache-edge
// update — so it can back both Reload and Preview.
func (e *Engine) renderConfig(ctx context.Context) (*traefikcfg.Result, []*store.Host, error) {
	hosts, err := e.st.ListHosts(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	mws, err := e.st.ListMiddlewares(ctx)
	if err != nil {
		return nil, nil, err
	}
	certs, err := e.st.ListCertificates(ctx)
	if err != nil {
		return nil, nil, err
	}
	acls, err := e.st.ListAccessLists(ctx)
	if err != nil {
		return nil, nil, err
	}
	bans, err := e.st.ListActiveBans(ctx)
	if err != nil {
		return nil, nil, err
	}
	bannedIPs := make([]string, 0, len(bans))
	for _, b := range bans {
		bannedIPs = append(bannedIPs, b.IP)
	}

	// Default Site: enabled unless explicitly turned off.
	dsMode, _ := e.st.GetSetting(ctx, "defaultsite.mode")
	defaultSiteEnabled := dsMode != "off" && dsMode != "disabled"

	// Raw passthrough (validated; a bad snippet fails the whole reload, keeping
	// the last-known-good config live).
	var rawCfg *dynamic.Configuration
	if rawYAML, err := e.st.GetSetting(ctx, "raw.dynamicYaml"); err == nil && rawYAML != "" {
		rawCfg, err = traefikcfg.ParseRawConfig(rawYAML)
		if err != nil {
			return nil, nil, fmt.Errorf("raw config: %w", err)
		}
	}

	// Plugin toggles.
	wafEnabled := e.wafEnabled(ctx)
	cacheEnabled := e.settingBool(ctx, "plugins.cache.enabled", false)
	var wafDirectives []string
	if s, _ := e.st.GetSetting(ctx, "plugins.waf.directives"); s != "" {
		_ = json.Unmarshal([]byte(s), &wafDirectives)
	}
	// "owasp-crs" ruleset loads the build-time-bundled real OWASP CRS instead of
	// the curated rules (falls back to curated if the bundle is missing).
	if rs, _ := e.st.GetSetting(ctx, "plugins.waf.ruleset"); rs == "owasp-crs" {
		if body, err := os.ReadFile(e.cfg.WAFCRSFile); err == nil && len(body) > 0 {
			var lines []string
			for _, l := range strings.Split(string(body), "\n") {
				if strings.TrimSpace(l) != "" {
					lines = append(lines, l)
				}
			}
			if len(lines) > 0 {
				wafDirectives = lines
			}
		} else {
			e.log.Warn("owasp-crs ruleset selected but bundle not found; using curated", "file", e.cfg.WAFCRSFile)
		}
	}

	res, err := traefikcfg.Render(traefikcfg.Inputs{
		Hosts:              hosts,
		Middlewares:        mws,
		Certificates:       certs,
		AccessLists:        acls,
		EntryPoints:        traefikcfg.EntryPoints{HTTP: e.cfg.HTTPEntryPoint, HTTPS: e.cfg.HTTPSEntryPoint},
		ChallengeBackend:   e.challengeBackend,
		ContentBackend:     e.challengeBackend,
		DefaultSiteEnabled: defaultSiteEnabled,
		RawConfig:          rawCfg,
		WAFEnabled:         wafEnabled,
		WAFDirectives:      wafDirectives,
		CacheEnabled:       cacheEnabled,
		CacheBackend:       e.cacheBackend,
		CacheToken:         e.cacheToken,
		ExternalCerts:      e.externalCerts(),
		BannedIPs:          bannedIPs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("render: %w", err)
	}
	if err := traefikcfg.ValidateConfig(res.Config); err != nil {
		return nil, nil, fmt.Errorf("validate: %w", err)
	}
	return res, hosts, nil
}

// ProviderDocument returns the JSON document to serve to Traefik over the HTTP
// provider, with certificate private keys injected, plus an ETag for cheap
// no-change polls.
func (e *Engine) ProviderDocument(ctx context.Context) (doc []byte, etag string, err error) {
	e.mu.RLock()
	res := e.rendered
	e.mu.RUnlock()
	if res == nil {
		// Serve an empty-but-valid config until the first successful render. Must be a
		// bare {} — an empty "http":{} section is rejected by Traefik's decoder as a
		// standalone element (same rule that makes the renderer prune empty sections).
		return []byte(`{}`), "empty", nil
	}
	doc, err = traefikcfg.InjectKeys(res.JSON, func(certID string) (string, error) {
		c, err := e.st.GetCertificate(ctx, certID)
		if err != nil {
			// InjectKeys omits this cert and serves the rest; log why.
			e.log.Error("provider: certificate lookup failed; omitting from served config", "cert", certID, "err", err)
			return "", err
		}
		pem, err := e.box.DecryptString(c.KeyPEMEnc)
		if err != nil {
			e.log.Error("provider: certificate key decrypt failed; omitting from served config", "cert", certID, "err", err)
			return "", err
		}
		return pem, nil
	})
	if err != nil {
		return nil, "", err
	}
	return doc, res.Hash, nil
}

// SyncStatic regenerates the static Traefik config from listeners + app config,
// writes it atomically, and — if it changed and Traefik is managed — performs a
// graceful restart. This is the ONLY path that restarts Traefik; everything else
// is hot-reloaded via the provider. forceRestart restarts even if unchanged.
func (e *Engine) SyncStatic(ctx context.Context, forceRestart bool) error {
	accessLog := e.settingBool(ctx, "traefik.accessLog", true)
	metrics := e.settingBool(ctx, "traefik.metrics", true)

	var plugins []traefikcfg.PluginDecl
	if e.wafEnabled(ctx) {
		plugins = append(plugins, traefikcfg.PluginDecl{Name: traefikcfg.WAFPluginName, ModuleName: traefikcfg.WAFModuleName, Version: traefikcfg.WAFModuleVersion})
	}

	yamlBytes, err := traefikcfg.RenderStatic(traefikcfg.StaticParams{
		HTTPEntryPoint:    e.cfg.HTTPEntryPoint,
		HTTPSEntryPoint:   e.cfg.HTTPSEntryPoint,
		HTTPPort:          e.cfg.HTTPPort,
		HTTPSPort:         e.cfg.HTTPSPort,
		ProviderEndpoint:  e.cfg.ProviderAdvertise + "/api/provider",
		ProviderToken:     e.cfg.ProviderToken,
		PollInterval:      e.cfg.ProviderPollInterval.String(),
		StreamEntryPoints: e.cfg.StreamEntryPoints,
		APIListen:         e.cfg.TraefikAPIListen,
		Plugins:           plugins,
		AccessLog:         accessLog,
		MetricsProm:       metrics,
	})
	if err != nil {
		return err
	}

	path := e.cfg.TraefikStaticCfg
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	changed := true
	if existing, err := os.ReadFile(path); err == nil {
		changed = hashBytes(existing) != hashBytes(yamlBytes)
	}
	if changed {
		if err := atomicWrite(path, yamlBytes); err != nil {
			return err
		}
		e.log.Info("static config written", "path", path)
	}

	if (changed || forceRestart) && e.cfg.TraefikManaged && e.sup.Status().State != supervisor.StateStopped {
		e.log.Info("static config changed; restarting traefik")
		if err := e.sup.Restart(ctx); err != nil {
			return fmt.Errorf("restart traefik: %w", err)
		}
	}
	return nil
}

// externalCerts scans the configured external-certs directory (BYO certs mode)
// for cert/key pairs and returns them for inline serving. Supports cert-manager's
// tls.crt/tls.key convention and <name>.crt|.pem + <name>.key pairs.
func (e *Engine) externalCerts() []traefikcfg.ExternalCert {
	dir := e.cfg.ExternalCertsDir
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []traefikcfg.ExternalCert
	for _, ent := range entries {
		name := ent.Name()
		ext := filepath.Ext(name)
		if ext != ".crt" && ext != ".pem" {
			continue
		}
		base := strings.TrimSuffix(name, ext)
		keyPath := filepath.Join(dir, base+".key")
		if _, err := os.Stat(keyPath); err != nil {
			continue
		}
		certPEM, err1 := os.ReadFile(filepath.Join(dir, name))
		keyPEM, err2 := os.ReadFile(keyPath)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, traefikcfg.ExternalCert{CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	}
	return out
}

// wafEnabled reports whether the Coraza WAF plugin is loaded. It defaults to
// cfg.WAFPreload (opt-out) when the plugins.waf.enabled setting is unset.
func (e *Engine) wafEnabled(ctx context.Context) bool {
	v, err := e.st.GetSetting(ctx, "plugins.waf.enabled")
	if err != nil {
		return e.cfg.WAFPreload
	}
	return v == "true" || v == "1"
}

func (e *Engine) settingBool(ctx context.Context, key string, def bool) bool {
	v, err := e.st.GetSetting(ctx, key)
	if err != nil {
		return def
	}
	return v == "true" || v == "1"
}

// Version returns the current served config version.
func (e *Engine) Version() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.version
}

// Rollback restores a previous snapshot as the served configuration. The
// snapshot JSON still contains @@KEY placeholders, so it serves correctly with
// current certificate keys. A subsequent edit + Reload supersedes it.
func (e *Engine) Rollback(ctx context.Context, version int64) error {
	snap, err := e.st.GetSnapshot(ctx, version)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.rendered = &traefikcfg.Result{JSON: []byte(snap.JSON), Hash: snap.Hash}
	e.mu.Unlock()
	// Record the rollback as a new snapshot so version history stays monotonic.
	next, _ := e.st.LatestSnapshotVersion(ctx)
	next++
	_ = e.st.AddSnapshot(ctx, &store.ConfigSnapshot{Version: next, JSON: snap.JSON, Hash: snap.Hash, Valid: true})
	e.mu.Lock()
	e.version = next
	e.mu.Unlock()
	e.log.Info("rolled back config", "from", version, "newVersion", next)
	return nil
}

// StartBackground launches periodic maintenance: session purge and certificate
// renewal checks. Each loop runs under panic recovery so a bug in one can never
// crash the process (PID 1).
func (e *Engine) StartBackground(ctx context.Context) {
	e.goSafe("renewal-loop", func() { e.renewalLoop(ctx) })
	e.goSafe("session-purge-loop", func() { e.sessionPurgeLoop(ctx) })
	e.goSafe("ban-prune-loop", func() { e.banPruneLoop(ctx) })
	e.goSafe("ban-reload-loop", func() { e.banReloadLoop(ctx) })
	e.StartScheduler(ctx)
}

// goSafe runs fn in a new goroutine with panic recovery, so a panic in a
// background task is logged instead of crashing PID 1 (and the supervised Traefik).
func (e *Engine) goSafe(name string, fn func()) {
	go func() {
		defer e.recover(name)
		fn()
	}()
}

// recoverGuard runs fn synchronously under panic recovery. It's the in-loop
// sibling of goSafe: a long-lived loop (e.g. the scheduler) calls it once per
// iteration so a panicking tick is logged and contained without tearing down the
// loop or spawning a goroutine.
func (e *Engine) recoverGuard(name string, fn func()) {
	defer e.recover(name)
	fn()
}

// recover logs a recovered panic for a named task. Call as `defer e.recover(name)`.
func (e *Engine) recover(name string) {
	if r := recover(); r != nil {
		e.log.Error("panic recovered in background task", "task", name, "panic", r, "stack", string(debug.Stack()))
	}
}

func (e *Engine) renewalLoop(ctx context.Context) {
	interval := e.cfg.RenewalInterval
	if interval <= 0 {
		interval = 12 * time.Hour
	}
	// Check shortly after boot, then every interval. The initial delay is capped at
	// the interval so a short (test/HA) interval isn't blocked by the 30s warmup.
	initial := 30 * time.Second
	if interval < initial {
		initial = interval
	}
	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			e.renewDueCertificates(ctx)
			timer.Reset(interval)
		}
	}
}

// renewDueCertificates renews ACME certs within 30 days of expiry (or failed).
// Across multiple instances sharing one database, only the lease holder renews
// (Round 4c leader election) to avoid duplicate orders / rate limits.
func (e *Engine) renewDueCertificates(ctx context.Context) {
	leaseTTL := e.cfg.RenewalLeaseTTL
	if leaseTTL <= 0 {
		leaseTTL = 15 * time.Minute
	}
	if ok, _ := e.st.AcquireLease(ctx, "acme-renewal", e.holderID, leaseTTL); !ok {
		e.log.Debug("not the ACME renewal leader; skipping")
		return
	}
	certs, err := e.st.ListCertificates(ctx)
	if err != nil {
		e.log.Error("renewal: list certs", "err", err)
		return
	}
	threshold := time.Now().Add(30 * 24 * time.Hour)
	var renewed bool
	for _, c := range certs {
		if c.Type != store.CertTypeACME || !c.AutoRenew {
			continue
		}
		due := c.Status == store.CertStatusFailed ||
			c.ExpiresAt == nil ||
			c.ExpiresAt.Before(threshold)
		if !due {
			continue
		}
		e.log.Info("renewing certificate", "domains", c.Domains)
		if err := e.acme.Obtain(ctx, c); err != nil {
			e.log.Error("renewal failed", "domains", c.Domains, "err", err)
			e.notifier.Notify(ctx, "error", "Certificate renewal failed",
				fmt.Sprintf("Renewal failed for %v: %v", c.Domains, err))
			continue
		}
		e.notifier.Notify(ctx, "info", "Certificate renewed",
			fmt.Sprintf("Successfully renewed certificate for %v.", c.Domains))
		renewed = true
	}
	if renewed {
		if _, err := e.Reload(ctx); err != nil {
			e.log.Error("reload after renewal", "err", err)
		}
	}
}

func (e *Engine) sessionPurgeLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.st.PurgeExpiredSessions(ctx)
		}
	}
}

// ConstantTimeEq compares two tokens without leaking timing information.
func ConstantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func hashBytes(b []byte) string {
	return traefikcfg.HashBytes(b)
}

func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

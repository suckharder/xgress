// Command xgress is a proxy manager for Traefik: a single binary that owns the proxy
// configuration in a database, serves it to a supervised Traefik process over
// the HTTP provider, manages certificates itself via ACME, and presents an
// NPM-style admin UI. In the single-container deployment it runs as PID 1 and
// supervises Traefik as a child; in the external-Traefik deployment it manages an
// external Traefik via a shared static-config file.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/api"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/edge"
	"github.com/suckharder/xgress/internal/engine"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
	"github.com/suckharder/xgress/internal/version"
	"github.com/suckharder/xgress/internal/webcontent"
	"github.com/suckharder/xgress/web"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("starting xgress",
		"version", version.Version, "traefik", version.TraefikVersion,
		"db", cfg.DBDriver, "managed", cfg.TraefikManaged)

	// Ensure data directories exist.
	for _, dir := range []string{cfg.DataDir, cfg.ACMEDir(), cfg.CertsDir(), filepath.Dir(cfg.TraefikStaticCfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	box, err := secrets.Load(cfg.SecretsKeyFile)
	if err != nil {
		return err
	}
	// Loudly surface a swapped/lost secrets key (otherwise encrypted material would
	// silently fail to decrypt at use time). Non-fatal: unencrypted features still work.
	if err := box.VerifyKey(cfg.SecretsKeyFile + ".canary"); err != nil {
		log.Error("SECRETS KEY MISMATCH", "err", err)
	}

	// Resolve the provider auth token (env > persisted > generate). It gates the
	// key-serving /api/provider endpoint and is embedded into Traefik's static config.
	if err := ensureProviderToken(cfg); err != nil {
		return fmt.Errorf("provider token: %w", err)
	}
	// Resolve the cache-edge auth token (env > persisted > generate). It gates the
	// native cache edge so it is safe to expose on the Docker network in external mode.
	if err := ensureEdgeToken(cfg); err != nil {
		return fmt.Errorf("edge token: %w", err)
	}

	// External-Traefik mode binds the provider + edge on the Docker network, so a
	// missing token would expose the decrypted-key endpoint / cache as an open proxy.
	// Tokens always auto-generate above, but enforce the invariant fail-closed (S2).
	if !cfg.TraefikManaged {
		if cfg.ProviderToken == "" || cfg.EdgeToken == "" {
			return fmt.Errorf("external-Traefik mode requires non-empty provider and edge tokens; set XGRESS_PROVIDER_TOKEN / XGRESS_EDGE_TOKEN (or let them auto-generate) — refusing to start with an ungated key endpoint")
		}
		// S1 mitigation: the provider serves decrypted TLS private keys, and both the
		// provider and edge listen over PLAINTEXT HTTP on the Docker network here —
		// protected only by the bearer token, not TLS. Warn so the operator keeps that
		// network trusted (a private overlay, not a shared bridge) and the tokens
		// secret. See docs/operations/trust-model.md.
		log.Warn("external-Traefik mode: the provider (which inlines decrypted TLS private keys) and the cache edge are served over PLAINTEXT HTTP on the Docker network, authenticated only by a bearer token — not TLS. Keep this network private and the tokens secret; see the trust-model docs.",
			"provider", cfg.ProviderListen, "edge", cfg.EdgeListen)
	}

	st, err := store.Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	// Challenge responder (served to Traefik via a high-priority route).
	responder := acme.NewHTTP01Responder()

	// The ACME HTTP-01 challenge route points Traefik back at xgress's provider/
	// challenge server. ProviderAdvertise is the URL Traefik uses to reach it
	// (loopback in single-container mode, service name in external-Traefik mode).
	challengeBackend := cfg.ProviderAdvertise

	staging := cfg.ACMEStaging || settingTrue(ctx, st, "acme.staging")
	email := cfg.ACMEEmail
	if v, err := st.GetSetting(ctx, "acme.email"); err == nil && v != "" {
		email = v
	}
	acmeMgr := acme.New(acme.Options{
		Store: st, Box: box, Responder: responder,
		DefaultEmail: email, Staging: staging,
		CADirURL:                cfg.ACMECAURL,
		DNSRecursiveNameservers: cfg.ACMEDNSResolvers,
		Logger:                  log,
	})

	sup := supervisor.New(supervisor.Options{
		Binary:       cfg.TraefikBinary,
		ConfigFile:   cfg.TraefikStaticCfg,
		WorkDir:      cfg.DataDir,
		Managed:      cfg.TraefikManaged,
		RestartDrain: cfg.RestartDrain,
		Logger:       log,
	})

	eng := engine.New(cfg, st, box, sup, acmeMgr, challengeBackend, log)

	// Native server-side cache edge (in-memory, or Redis for a shared cache).
	var cacheStore edge.CacheStore
	if cfg.RedisURL != "" {
		rs, err := edge.NewRedisStore(cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("redis cache: %w", err)
		}
		cacheStore = rs
		log.Info("server-side cache: redis", "url", cfg.RedisURL)
	} else {
		cacheStore = edge.NewMemStore(ctx, edge.MemLimits{
			MaxBytes:      cfg.CacheMaxBytes,
			MaxEntryBytes: cfg.CacheMaxEntryBytes,
		})
	}
	cacheEdge := edge.New(cacheStore, cfg.CacheTTL, cfg.EdgeToken, log)
	cacheEdge.SetEntryLimit(cfg.CacheMaxEntryBytes)
	cacheEdge.SetWAFResponseFailClosed(cfg.WAFResponseFailClosed)
	eng.SetCacheEdge(cacheEdge, cfg.EdgeAdvertise, cfg.EdgeToken)

	assets, err := web.Assets()
	if err != nil {
		return err
	}
	srv := api.NewServer(cfg, st, eng, box, assets, log)

	// Bootstrap: render config, write static config, start Traefik.
	if err := eng.Bootstrap(ctx); err != nil {
		return err
	}
	eng.StartBackground(ctx)

	// Provider + challenge + content server on loopback (no auth; Traefik-only).
	providerMux := http.NewServeMux()
	providerMux.Handle("/api/provider", srv.ProviderHandler())
	providerMux.Handle("/healthz", srv.ProviderHandler())
	providerMux.Handle("/.well-known/acme-challenge/", responder)
	webcontent.New(st).Register(providerMux) // default-site + custom error pages

	// Conservative timeouts on every server: ReadHeaderTimeout blocks Slowloris on
	// headers; Read/Write/Idle bound slow bodies, slow clients, and idle keep-alives
	// so a connection can't be held open indefinitely. Generous enough for backups
	// and the buffered cache-edge proxy.
	timeouts := func(addr string, h http.Handler) *http.Server {
		return &http.Server{
			Addr: addr, Handler: h,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
	}
	providerSrv := timeouts(cfg.ProviderListen, providerMux)
	adminSrv := timeouts(cfg.AdminListen, srv.AdminHandler())
	edgeSrv := timeouts(cfg.EdgeListen, cacheEdge)

	errCh := make(chan error, 3)
	go func() {
		log.Info("cache edge listening", "addr", cfg.EdgeListen)
		if err := edgeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Info("provider endpoint listening", "addr", cfg.ProviderListen)
		if err := providerSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Info("admin UI + API listening", "addr", cfg.AdminListen)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		log.Error("server error", "err", err)
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shutCtx)
	_ = providerSrv.Shutdown(shutCtx)
	_ = edgeSrv.Shutdown(shutCtx)
	if err := sup.Stop(); err != nil {
		log.Warn("error stopping traefik", "err", err)
	}
	return nil
}

func settingTrue(ctx context.Context, st *store.Store, key string) bool {
	v, err := st.GetSetting(ctx, key)
	return err == nil && (v == "true" || v == "1")
}

// ensureProviderToken resolves the provider auth token: an explicit
// XGRESS_PROVIDER_TOKEN wins; otherwise a previously-persisted token is reused; on
// first boot a random one is generated and persisted (0600), so the same value is
// used by both the provider gate and the rendered Traefik static config.
func ensureProviderToken(cfg *config.Config) error {
	tok, err := resolveToken(cfg.ProviderToken, cfg.ProviderTokenFile())
	if err != nil {
		return err
	}
	cfg.ProviderToken = tok
	return nil
}

// ensureEdgeToken resolves the cache-edge auth token (same env > persisted >
// generate logic as the provider token). It gates the native cache edge so it can be
// exposed on the Docker network in external mode without becoming an open proxy.
func ensureEdgeToken(cfg *config.Config) error {
	tok, err := resolveToken(cfg.EdgeToken, cfg.EdgeTokenFile())
	if err != nil {
		return err
	}
	cfg.EdgeToken = tok
	return nil
}

// resolveToken returns explicit if set, else a token persisted at path, else a
// freshly generated one persisted (0600) at path.
func resolveToken(explicit, path string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		if tok := strings.TrimSpace(string(b)); tok != "" {
			return tok, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

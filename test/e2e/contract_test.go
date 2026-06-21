//go:build integration

// Package e2e contains xgress's end-to-end tiers. Tier A (this file) is the
// config-contract test: it runs xgress's engine/store/provider IN-PROCESS (real
// code, seeded sqlite, fine-grained assertions) and drives a REAL pinned Traefik
// process against the in-process provider + a dummy upstream. It proves the full
// DB → render → serve → Traefik-consumes loop, and locks the two classic gotchas
// (empty-section pruning and @@KEY injection) against an actual Traefik.
//
// Run with: make integration   (or: go test -tags integration ./test/e2e/...)
package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/suckharder/xgress/internal/api"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/engine"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

const upstreamMarker = "xgress-E2E-UPSTREAM-OK"

// contractHarness is the in-process xgress side of a Tier A test: a seeded store, a
// real engine (unmanaged supervisor), and the real provider handler served over
// loopback. Each test seeds its own hosts, builds its StaticParams, and runs
// Traefik via env. Shared by TestConfigContract and TestStreamRouting.
type contractHarness struct {
	env      traefikEnv
	cfg      *config.Config
	st       *store.Store
	box      *secrets.Box
	eng      *engine.Engine
	provider string // provider endpoint URL, already reachable() from the Traefik process
}

func newContractHarness(t *testing.T) *contractHarness {
	t.Helper()
	env := newTraefikEnv(t)
	ctx := context.Background()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:         dir,
		DBDriver:        config.DriverSQLite,
		HTTPEntryPoint:  "web",
		HTTPSEntryPoint: "websecure",
		ProviderToken:   "e2e-provider-token", // exercises the real token gate end to end
	}
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatalf("secrets.Load: %v", err)
	}
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: discardLogger()})
	eng := engine.New(cfg, st, box, sup, nil, "", discardLogger())

	// REAL provider handler (token gate + ETag/304), served over loopback.
	provider := httptest.NewServer(api.NewServer(cfg, st, eng, box, fstest.MapFS{}, discardLogger()).ProviderHandler())
	t.Cleanup(provider.Close)
	provHost, provPort := hostPort(t, provider.URL)
	return &contractHarness{
		env: env, cfg: cfg, st: st, box: box, eng: eng,
		provider: fmt.Sprintf("http://%s:%d/api/provider", env.reachable(provHost), provPort),
	}
}

func TestConfigContract(t *testing.T) {
	h := newContractHarness(t)
	env, eng, st, box, cfg := h.env, h.eng, h.st, h.box, h.cfg
	providerEndpoint := h.provider
	ctx := context.Background()

	// Dummy upstream the proxy host points at.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", upstreamMarker, r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	upHost, upPort := hostPort(t, upstream.URL)

	// ---- seed the database ----
	// A plain proxy host (HTTP), and a TLS host backed by an uploaded cert.
	appHost := &store.Host{
		Kind: store.HostKindProxy, Enabled: true, Domains: []string{"app.test"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: env.reachable(upHost), Port: upPort}},
		TLS:       store.TLSNone,
	}
	if err := st.CreateHost(ctx, appHost); err != nil {
		t.Fatalf("create app host: %v", err)
	}

	certPEM, keyPEM := selfSignedCert(t, "tls.test")
	keyEnc, err := box.EncryptString(keyPEM)
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	if err := st.CreateCertificate(ctx, &store.Certificate{
		Type: store.CertTypeUploaded, Domains: []string{"tls.test"},
		CertPEM: certPEM, KeyPEMEnc: keyEnc, Status: store.CertStatusValid,
	}); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	tlsHost := &store.Host{
		Kind: store.HostKindProxy, Enabled: true, Domains: []string{"tls.test"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: env.reachable(upHost), Port: upPort}},
		TLS:       store.TLSCustom,
	}
	if err := st.CreateHost(ctx, tlsHost); err != nil {
		t.Fatalf("create tls host: %v", err)
	}

	// Render + snapshot so the provider serves the seeded config.
	if _, err := eng.Reload(ctx); err != nil {
		t.Fatalf("engine.Reload: %v", err)
	}

	// ---- launch the real Traefik ----
	ports := freePorts(t, 3)
	params := traefikcfg.StaticParams{
		HTTPEntryPoint:   "web",
		HTTPSEntryPoint:  "websecure",
		HTTPPort:         ports[0],
		HTTPSPort:        ports[1],
		ProviderEndpoint: providerEndpoint,
		ProviderToken:    cfg.ProviderToken,
		PollInterval:     "1s",
		APIListen:        fmt.Sprintf("127.0.0.1:%d", ports[2]),
		LogLevel:         "INFO",
	}
	eps, stop := env.run(t, params)
	defer stop()

	// ---- assertions ----

	// A2: a request through the web entrypoint reaches the upstream (also proves the
	// provider document was consumed and the router is live). Polled: Traefik's first
	// provider poll happens ~1s after start.
	eventually(t, 6*time.Second, func() error {
		body, code, err := httpGetHost(eps.web+"/hello", "app.test")
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("status %d (body %q)", code, body)
		}
		if !strings.Contains(body, upstreamMarker) {
			return fmt.Errorf("response %q missing upstream marker", body)
		}
		return nil
	})

	// A1: Traefik's API reports the router loaded and enabled.
	eventually(t, 6*time.Second, func() error {
		routers, err := traefikRouters(eps.api)
		if err != nil {
			return err
		}
		for _, r := range routers {
			if strings.HasPrefix(r.Name, "host-"+appHost.ID+"@") {
				if r.Status != "enabled" {
					return fmt.Errorf("router %s status=%q, want enabled", r.Name, r.Status)
				}
				return nil
			}
		}
		return fmt.Errorf("router host-%s not found among %d routers", appHost.ID, len(routers))
	})

	// A5: @@KEY injection end to end — Traefik must serve the exact uploaded leaf on
	// the HTTPS entrypoint, which only works if the decrypted key was spliced in at
	// serve time. SNI selects the cert; we verify the presented leaf's SAN.
	eventually(t, 6*time.Second, func() error {
		conn, err := tls.Dial("tcp", eps.websecure, &tls.Config{
			ServerName:         "tls.test",
			InsecureSkipVerify: true, //nolint:gosec // self-signed test cert; we assert the SAN ourselves
		})
		if err != nil {
			return err
		}
		defer conn.Close()
		peer := conn.ConnectionState().PeerCertificates
		if len(peer) == 0 {
			return fmt.Errorf("no peer certificate presented")
		}
		for _, name := range peer[0].DNSNames {
			if name == "tls.test" {
				return nil
			}
		}
		return fmt.Errorf("served cert SAN %v does not include tls.test", peer[0].DNSNames)
	})

	// A3: a DB change propagates to Traefik within the poll budget (~3s). Disable the
	// app host; the route must start returning 404 (no catch-all is configured).
	appHost.Enabled = false
	if err := st.UpdateHost(ctx, appHost); err != nil {
		t.Fatalf("disable app host: %v", err)
	}
	if _, err := eng.Reload(ctx); err != nil {
		t.Fatalf("reload after disable: %v", err)
	}
	eventually(t, 3*time.Second, func() error {
		_, code, err := httpGetHost(eps.web+"/hello", "app.test")
		if err != nil {
			return err
		}
		if code != http.StatusNotFound {
			return fmt.Errorf("status %d, want 404 after disable+reload", code)
		}
		return nil
	})

	// A4: empty-section pruning + clean contract — across the whole run (HTTP-only,
	// then +TLS, never TCP/UDP), Traefik must never have failed to decode the served
	// config. This is the assertion that auto-catches the "tcp cannot be a standalone
	// element" class of regressions.
	logs := eps.logs.String()
	for _, bad := range []string{"standalone element", "cannot decode configuration", "error while building configuration"} {
		if strings.Contains(logs, bad) {
			t.Errorf("Traefik reported a config-decode problem (%q) — pruning/contract regression:\n%s", bad, logs)
		}
	}
}

// hostPort splits an http(s)://host:port URL into its host and numeric port.
func hostPort(t *testing.T, rawurl string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawurl, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port from %q: %v", rawurl, err)
	}
	return u.Hostname(), p
}

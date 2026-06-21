package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/store"
)

func TestAccessorsAndConstantTime(t *testing.T) {
	e := newTestEngine(t)
	// Trivial accessors must be wired and non-nil.
	if e.Supervisor() == nil || e.TraefikAPI() == nil || e.Notifier() == nil {
		t.Error("an accessor returned nil")
	}
	if e.ACME() != nil {
		t.Error("test engine ACME should be nil (none wired)")
	}
	// Cache name is "" until an edge is wired.
	if e.CacheBackendName() != "" {
		t.Errorf("cache name without edge = %q, want empty", e.CacheBackendName())
	}
	// SecurityMetrics + WAFEnabled don't panic and return a value.
	_ = e.SecurityMetrics()
	_ = e.WAFEnabled(context.Background())

	// ConstantTimeEq is a correct equality.
	if !ConstantTimeEq("abc", "abc") || ConstantTimeEq("abc", "abd") || ConstantTimeEq("abc", "ab") {
		t.Error("ConstantTimeEq incorrect")
	}
	if hashBytes([]byte("x")) == hashBytes([]byte("y")) {
		t.Error("hashBytes collision")
	}
}

func TestSyncStaticWritesConfig(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "traefik.yml")
	e.cfg.TraefikStaticCfg = path

	if err := e.SyncStatic(ctx, false); err != nil {
		t.Fatalf("SyncStatic: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("static config not written: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "entryPoints") || !strings.Contains(s, "providers") {
		t.Errorf("static config missing core sections:\n%s", s)
	}
	// Second call with no change must not error (idempotent; unmanaged → no restart).
	if err := e.SyncStatic(ctx, false); err != nil {
		t.Fatalf("idempotent SyncStatic: %v", err)
	}
}

func TestExternalCertsServed(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "site.crt"), []byte("CERTDATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "site.key"), []byte("KEYDATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A .crt without a matching .key is ignored.
	_ = os.WriteFile(filepath.Join(dir, "orphan.crt"), []byte("X"), 0o600)
	e.cfg.ExternalCertsDir = dir

	certs := e.externalCerts()
	if len(certs) != 1 || certs[0].CertPEM != "CERTDATA" || certs[0].KeyPEM != "KEYDATA" {
		t.Fatalf("externalCerts = %+v, want one site cert", certs)
	}
	// And they make it into the served document.
	res, err := e.Reload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.JSON), "CERTDATA") {
		t.Error("external cert not present in rendered config")
	}
}

func TestProviderDocumentInjectsKey(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	// An uploaded cert with an encrypted private key.
	keyEnc, err := e.box.EncryptString("-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----")
	if err != nil {
		t.Fatal(err)
	}
	c := &store.Certificate{
		Type: store.CertTypeUploaded, Domains: []string{"tls.example.com"},
		CertPEM:   "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
		KeyPEMEnc: keyEnc, Status: store.CertStatusValid,
	}
	if err := e.st.CreateCertificate(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	doc, etag, err := e.ProviderDocument(ctx)
	if err != nil {
		t.Fatalf("ProviderDocument: %v", err)
	}
	if etag == "" {
		t.Error("expected a non-empty ETag")
	}
	s := string(doc)
	if strings.Contains(s, "@@KEY:") {
		t.Error("key placeholder not replaced in served document")
	}
	if !strings.Contains(s, "SECRET") {
		t.Error("decrypted key not injected into served document")
	}
}

func TestProviderDocumentEmptyBeforeReload(t *testing.T) {
	e := newTestEngine(t)
	doc, etag, err := e.ProviderDocument(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if etag != "empty" || strings.TrimSpace(string(doc)) != "{}" {
		t.Errorf("pre-reload document = %s (etag %q), want bare {}", doc, etag)
	}
}

func TestRunSchedulesFlipsEnabled(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	h := &store.Host{Kind: store.HostKindProxy, Enabled: true, Domains: []string{"sched.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone}
	if err := e.st.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// A wildcard cron matches any minute → the disable action must flip the host.
	if err := e.st.CreateSchedule(ctx, &store.Schedule{HostID: h.ID, Action: "disable", Cron: "* * * * *"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	v0 := e.Version()
	e.runSchedules(ctx, time.Now())

	got, _ := e.st.GetHost(ctx, h.ID)
	if got.Enabled {
		t.Error("schedule did not disable the host")
	}
	if e.Version() <= v0 {
		t.Error("schedule change did not trigger a reload")
	}
	// Running again is a no-op (already disabled) — version must not advance.
	v1 := e.Version()
	e.runSchedules(ctx, time.Now())
	if e.Version() != v1 {
		t.Error("idempotent schedule run should not reload again")
	}
}

func TestBanReloadLoopDebouncesAndReloads(t *testing.T) {
	e := newTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	v0 := e.Version()

	go e.banReloadLoop(ctx)
	// Add a ban directly + request a debounced reload (as the auto-ban path does).
	if err := e.st.AddBan(ctx, &store.Ban{IP: "203.0.113.9", Reason: "test", Manual: false}); err != nil {
		t.Fatal(err)
	}
	e.scheduleBanReload()
	e.scheduleBanReload() // coalesced

	deadline := time.After(5 * time.Second)
	for e.Version() <= v0 {
		select {
		case <-deadline:
			t.Fatal("debounced reload did not run within 5s")
		case <-time.After(50 * time.Millisecond):
		}
	}
	doc, _, _ := e.ProviderDocument(ctx)
	if !strings.Contains(string(doc), "203.0.113.9") {
		t.Error("debounced reload did not include the new ban")
	}
}

func TestStartBackgroundIsCancelSafe(t *testing.T) {
	e := newTestEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	// Starts every maintenance loop under panic recovery; cancelling must unwind
	// them all cleanly (no panic, no leak failing the race detector).
	e.StartBackground(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}

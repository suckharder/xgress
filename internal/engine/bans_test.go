package engine

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/secmetrics"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
)

// newTestEngine builds an engine backed by a throwaway SQLite store in a temp
// dir, with an unmanaged (inert) supervisor — enough to exercise the auto-ban
// evaluator and the render path it triggers.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:         dir,
		DBDriver:        config.DriverSQLite,
		HTTPEntryPoint:  "web",
		HTTPSEntryPoint: "websecure",
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatalf("secrets: %v", err)
	}
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: slog.Default()})
	e := New(cfg, st, box, sup, nil, "http://127.0.0.1:9000", slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	// New() wires a notifier; nil-out logger noise but keep notifier (no-op without config).
	return e
}

// P1-7: BanConfig is cached so the hot WAF-block path doesn't read 4 settings per
// event; SetBanConfig must refresh that cache immediately.
func TestBanConfigCachedAndRefreshedOnSet(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	if c := e.BanConfig(ctx); c.Enabled {
		t.Fatal("auto-ban should default to disabled")
	}
	if e.banConfig.Load() == nil {
		t.Error("reading BanConfig should populate the cache")
	}

	if err := e.SetBanConfig(ctx, BanConfig{Enabled: true, Threshold: 3, WindowSec: 60, DurationSec: 120}); err != nil {
		t.Fatalf("SetBanConfig: %v", err)
	}
	c := e.BanConfig(ctx)
	if !c.Enabled || c.Threshold != 3 || c.WindowSec != 60 || c.DurationSec != 120 {
		t.Errorf("cache not refreshed after SetBanConfig: %+v", c)
	}
	// The cached value must match a fresh DB load (cache stays consistent).
	if got := e.loadBanConfig(ctx); got != c {
		t.Errorf("cached %+v != DB %+v", c, got)
	}
}

// S3: a WAF engine build failure is tracked (and surfaced on /api/health) instead of
// silently leaving WAF hosts uninspected. recordWAFStatus drives the status + alert.
func TestWAFStatusTracking(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	if !e.WAFStatus().Healthy {
		t.Fatal("WAF status should start healthy")
	}
	e.recordWAFStatus(ctx, false, "bad seclang directive")
	if s := e.WAFStatus(); s.Healthy || s.Error != "bad seclang directive" {
		t.Errorf("after build failure = %+v, want unhealthy with the error", s)
	}
	e.recordWAFStatus(ctx, true, "")
	if s := e.WAFStatus(); !s.Healthy || s.Error != "" {
		t.Errorf("after recovery = %+v, want healthy", s)
	}
}

// P1-7: the preloaded-settings bool helper matches settingBool's semantics
// (absent key → default; present-but-empty → false).
func TestSettingBoolMap(t *testing.T) {
	m := map[string]string{"on": "true", "off": "false", "one": "1", "empty": ""}
	cases := []struct {
		key  string
		def  bool
		want bool
	}{
		{"on", false, true},
		{"off", true, false},
		{"one", false, true},
		{"empty", true, false}, // present-but-empty parses false, not the default
		{"absent", true, true}, // missing key falls back to the default
		{"absent", false, false},
	}
	for _, tc := range cases {
		if got := settingBoolMap(m, tc.key, tc.def); got != tc.want {
			t.Errorf("settingBoolMap(%q, def=%v) = %v, want %v", tc.key, tc.def, got, tc.want)
		}
	}
}

func TestAutoBanWindow(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// Enable auto-ban: 3 blocks within 60s → ban for 120s.
	if err := e.SetBanConfig(ctx, BanConfig{Enabled: true, Threshold: 3, WindowSec: 60, DurationSec: 120}); err != nil {
		t.Fatalf("set ban config: %v", err)
	}

	ev := func(ip string) secmetrics.Event {
		return secmetrics.Event{At: time.Now(), ClientIP: ip, Blocked: true, RuleID: "942100"}
	}

	// Two blocks: below threshold, no ban yet.
	e.onWAFEvent(ev("198.51.100.5"))
	e.onWAFEvent(ev("198.51.100.5"))
	if banned, _ := e.st.IsActivelyBanned(ctx, "198.51.100.5"); banned {
		t.Fatal("IP banned before crossing threshold")
	}

	// Third block crosses the threshold → ban.
	e.onWAFEvent(ev("198.51.100.5"))
	banned, err := e.st.IsActivelyBanned(ctx, "198.51.100.5")
	if err != nil {
		t.Fatal(err)
	}
	if !banned {
		t.Fatal("IP not banned after crossing threshold")
	}

	// A different IP with a single block stays unbanned (per-IP windows).
	e.onWAFEvent(ev("198.51.100.9"))
	if banned, _ := e.st.IsActivelyBanned(ctx, "198.51.100.9"); banned {
		t.Fatal("unrelated IP banned")
	}

	// Auto-ban schedules a *debounced* reload (banReloadLoop, not started in this
	// unit test), so render explicitly and assert the deny router includes the IP.
	if _, err := e.Reload(ctx); err != nil {
		t.Fatalf("reload: %v", err)
	}
	doc := string(e.rendered.JSON)
	if !strings.Contains(doc, "ClientIP(`198.51.100.5`)") {
		t.Fatal("rendered config missing deny router for banned IP")
	}
	if !strings.Contains(doc, "xgress-banned-http") {
		t.Fatal("rendered config missing xgress-banned-http router")
	}
}

func TestAutoBanDisabledByDefault(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	// No config set → disabled. Many blocks must not ban.
	for i := 0; i < 10; i++ {
		e.onWAFEvent(secmetrics.Event{At: time.Now(), ClientIP: "203.0.113.50", Blocked: true})
	}
	if banned, _ := e.st.IsActivelyBanned(ctx, "203.0.113.50"); banned {
		t.Fatal("auto-ban fired while disabled (must be opt-in)")
	}
	cfg := e.BanConfig(ctx)
	if cfg.Enabled {
		t.Fatal("auto-ban enabled by default; must default off")
	}
}

func TestSweepBanHits(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()
	if err := e.SetBanConfig(ctx, BanConfig{Enabled: true, Threshold: 5, WindowSec: 60, DurationSec: 120}); err != nil {
		t.Fatal(err)
	}
	e.banMu.Lock()
	e.banHits["1.2.3.4"] = []time.Time{time.Now().Add(-2 * time.Minute)} // stale (> 60s window)
	e.banHits["5.6.7.8"] = []time.Time{time.Now()}                       // fresh
	e.banMu.Unlock()

	e.sweepBanHits(ctx)

	e.banMu.Lock()
	defer e.banMu.Unlock()
	if _, ok := e.banHits["1.2.3.4"]; ok {
		t.Error("stale banHits entry was not swept (unbounded growth)")
	}
	if _, ok := e.banHits["5.6.7.8"]; !ok {
		t.Error("fresh banHits entry was wrongly swept")
	}
}

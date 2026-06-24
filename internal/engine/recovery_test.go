package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/supervisor"
)

// TestWatchFatalLogTripsOnSignature verifies the first-fatal-signature observer:
// it ignores Traefik's own JSON logs, trips on a raw runtime crash line, and
// (via the supervisor's single-flight latch) fires recovery exactly once for a
// burst of stack-trace lines.
func TestWatchFatalLogTripsOnSignature(t *testing.T) {
	e := newTestEngine(t)
	var tripped int32
	e.sup.SetOnCrashLoop(func() { atomic.AddInt32(&tripped, 1) })

	// A JSON log line (Traefik's structured output) must never trip recovery, even
	// if it happens to contain a scary substring.
	e.watchFatalLog(supervisor.LogLine{Raw: `{"level":"error","message":"panic: runtime error in a user rule"}`})
	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&tripped) != 0 {
		t.Fatal("a JSON log line must not trip recovery")
	}

	// Raw (non-JSON) fatal signatures trip — but only once for the whole burst.
	e.watchFatalLog(supervisor.LogLine{Raw: "fatal error: runtime: split stack overflow"})
	e.watchFatalLog(supervisor.LogLine{Raw: "goroutine 1 [running]:"})
	e.watchFatalLog(supervisor.LogLine{Raw: "signal SIGSEGV: segmentation violation code=0x1"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&tripped) == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&tripped); got != 1 {
		t.Errorf("expected exactly one recovery trip for the crash burst, got %d", got)
	}
}

// TestWriteMinimalStatic checks the last-resort static config: entrypoints +
// provider only, with all extras stripped, so Traefik always boots.
func TestWriteMinimalStatic(t *testing.T) {
	e := newTestEngine(t)
	e.cfg.TraefikStaticCfg = filepath.Join(e.cfg.DataDir, "traefik", "traefik.yml")
	e.cfg.ProviderAdvertise = "http://127.0.0.1:9000"
	e.cfg.HTTPPort, e.cfg.HTTPSPort = 80, 443
	e.cfg.ProviderPollInterval = time.Second

	if err := e.writeMinimalStatic(); err != nil {
		t.Fatalf("writeMinimalStatic: %v", err)
	}
	b, err := os.ReadFile(e.cfg.TraefikStaticCfg)
	if err != nil {
		t.Fatalf("read static: %v", err)
	}
	s := string(b)
	for _, banned := range []string{"experimental", "prometheus", "accessLog", "insecure: true"} {
		if strings.Contains(s, banned) {
			t.Errorf("minimal static config must omit %q:\n%s", banned, s)
		}
	}
	if !strings.Contains(s, "/api/provider") {
		t.Errorf("minimal static config must keep the HTTP provider:\n%s", s)
	}
}

// TestRecoveryLadderEscalates drives the full escalation ladder and asserts each
// step's audited side effect, ending with the minimal static config on disk.
func TestRecoveryLadderEscalates(t *testing.T) {
	e := newTestEngine(t)
	e.recoverHealthWindow = 50 * time.Millisecond // don't wait 35s for the health-reset goroutine
	e.cfg.TraefikManaged = true                   // run the ladder; the inert supervisor's Restart is a logged no-op
	e.cfg.TraefikStaticCfg = filepath.Join(e.cfg.DataDir, "traefik", "traefik.yml")
	e.cfg.ProviderAdvertise = "http://127.0.0.1:9000"
	e.cfg.HTTPPort, e.cfg.HTTPSPort = 80, 443
	e.cfg.ProviderPollInterval = time.Second
	ctx := context.Background()

	// Seed a custom raw config (level-0 clears it) and two snapshots (level-1 rolls back).
	if err := e.st.SetSetting(ctx, "raw.dynamicYaml", "http: {}"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Reload(ctx); err != nil { // snapshot v1
		t.Fatalf("reload: %v", err)
	}
	if _, err := e.Reload(ctx); err != nil { // snapshot v2 (current)
		t.Fatalf("reload: %v", err)
	}

	// Level 0: clears the raw config.
	e.recoverTraefik(ctx)
	if v, _ := e.st.GetSetting(ctx, "raw.dynamicYaml"); v != "" {
		t.Errorf("level 0 must clear raw config, got %q", v)
	}
	if rs := e.RecoveryState(); rs.Level != 1 || rs.LastAction == "" {
		t.Errorf("after level 0, RecoveryState = %+v, want level 1 + an action", rs)
	}

	// Level 1: rolls back to the last-known-good snapshot.
	e.recoverTraefik(ctx)
	if rs := e.RecoveryState(); rs.Level != 2 {
		t.Errorf("after level 1, escalation level = %d, want 2", rs.Level)
	}

	// Level 2: writes the minimal static config so Traefik always boots.
	e.recoverTraefik(ctx)
	b, err := os.ReadFile(e.cfg.TraefikStaticCfg)
	if err != nil {
		t.Fatalf("minimal static not written: %v", err)
	}
	if strings.Contains(string(b), "experimental") || strings.Contains(string(b), "prometheus") {
		t.Errorf("level-2 static config is not minimal:\n%s", string(b))
	}
	if rs := e.RecoveryState(); rs.Level != 3 {
		t.Errorf("escalation level = %d, want 3", rs.Level)
	}
}

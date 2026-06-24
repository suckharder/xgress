package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

// fatalSignatures are non-JSON Traefik stderr markers of a hard crash (a Go
// runtime fault or panic). Matched case-insensitively. JSON lines (Traefik's own
// structured logs) are skipped to avoid false reverts.
var fatalSignatures = []string{
	"fatal error:",
	"runtime: split stack overflow",
	"signal sigsegv",
	"panic: runtime error",
}

// healthyRecoveryWindow is how long Traefik must stay up after a recovery restart
// before the escalation ladder resets to level 0.
const defaultRecoverHealthWindow = 35 * time.Second

// watchFatalLog trips recovery on the FIRST fatal-crash signature, so a slow
// compile-to-crash (which never fills the 3-in-10s window) is still caught. The
// supervisor's single-flight latch ensures a burst of stack-trace lines triggers
// exactly one recovery.
func (e *Engine) watchFatalLog(ll supervisor.LogLine) {
	raw := strings.TrimSpace(ll.Raw)
	if raw == "" || json.Valid([]byte(raw)) {
		return // Traefik's own logs are JSON; only react to raw runtime output
	}
	low := strings.ToLower(raw)
	for _, sig := range fatalSignatures {
		if strings.Contains(low, sig) {
			e.log.Error("traefik fatal signature detected; tripping recovery", "line", raw)
			e.sup.TripCrashLoop()
			return
		}
	}
}

// OnTraefikCrashLoop is the supervisor's crash-loop callback. It runs the bounded,
// audited recovery ladder under panic recovery (so a recovery bug can't crash PID 1).
func (e *Engine) OnTraefikCrashLoop() {
	e.recoverGuard("traefik-recovery", func() { e.recoverTraefik(context.Background()) })
}

// recoverTraefik takes one escalation step and restarts Traefik. The ladder never
// leaves the proxy down: each step makes the served config strictly safer.
//
//	level 0: clear any custom raw config + re-render
//	level 1: roll back to the last-known-good dynamic snapshot
//	level 2+: write a minimal static config (entrypoints + provider only)
func (e *Engine) recoverTraefik(ctx context.Context) {
	if !e.cfg.TraefikManaged {
		return // external Traefik: xgress doesn't own the process
	}
	e.recoverMu.Lock()
	level := e.recoverLevel
	e.recoverLevel++
	e.recoverMu.Unlock()

	if level > 0 {
		time.Sleep(2 * time.Second) // back off between escalation steps
	}

	var action string
	switch level {
	case 0:
		action = "cleared custom raw config and re-rendered dynamic config"
		_ = e.st.SetSetting(ctx, "raw.dynamicYaml", "")
		if _, err := e.Reload(ctx); err != nil {
			e.log.Error("recovery: re-render after raw clear", "err", err)
		}
	case 1:
		if v, ok := e.lastGoodVersion(ctx); ok {
			action = fmt.Sprintf("rolled back to last-known-good config v%d", v)
			if err := e.Rollback(ctx, v); err != nil {
				e.log.Error("recovery: rollback", "err", err)
			}
		} else {
			action = "no prior snapshot; re-rendered current config"
			_, _ = e.Reload(ctx)
		}
	default:
		action = "wrote minimal static config (entrypoints + HTTP provider only)"
		if err := e.writeMinimalStatic(); err != nil {
			e.log.Error("recovery: write minimal static", "err", err)
		}
	}

	e.recordRecovery(ctx, level, action)

	// Re-render happened before this restart (above), so the served config never
	// dangles a reference to whatever we just disabled. Restart resets the crash-loop
	// latch, giving the recovered run a fresh window.
	if err := e.sup.Restart(ctx); err != nil {
		e.log.Error("recovery: restart traefik", "err", err)
	}
	e.goSafe("recovery-health-reset", e.resetRecoveryOnHealth)
}

// lastGoodVersion returns the highest valid snapshot version older than the
// current served version.
func (e *Engine) lastGoodVersion(ctx context.Context) (int64, bool) {
	cur := e.Version()
	snaps, err := e.st.ListSnapshots(ctx, 50)
	if err != nil {
		return 0, false
	}
	best := int64(-1)
	for _, s := range snaps {
		if s.Valid && s.Version < cur && s.Version > best {
			best = s.Version
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

// writeMinimalStatic writes a bare-bones static config so Traefik always boots.
func (e *Engine) writeMinimalStatic() error {
	y, err := traefikcfg.RenderStatic(traefikcfg.StaticParams{
		HTTPEntryPoint:   e.cfg.HTTPEntryPoint,
		HTTPSEntryPoint:  e.cfg.HTTPSEntryPoint,
		HTTPPort:         e.cfg.HTTPPort,
		HTTPSPort:        e.cfg.HTTPSPort,
		ProviderEndpoint: e.cfg.ProviderAdvertise + "/api/provider",
		ProviderToken:    e.cfg.ProviderToken,
		PollInterval:     e.cfg.ProviderPollInterval.String(),
		Minimal:          true,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.cfg.TraefikStaticCfg), 0o755); err != nil {
		return err
	}
	return atomicWrite(e.cfg.TraefikStaticCfg, y)
}

// resetRecoveryOnHealth clears the escalation ladder once Traefik stays up.
func (e *Engine) resetRecoveryOnHealth() {
	time.Sleep(e.recoverHealthWindow)
	st := e.sup.Status()
	if st.State == supervisor.StateRunning && !st.CrashLoop {
		e.recoverMu.Lock()
		if e.recoverLevel > 0 {
			e.log.Info("traefik recovered; escalation level reset", "from", e.recoverLevel)
			e.recoverLevel = 0
		}
		e.recoverMu.Unlock()
	}
}

func (e *Engine) recordRecovery(ctx context.Context, level int, action string) {
	e.recoverMu.Lock()
	e.lastRecovery = action
	e.lastRecoveryAt = time.Now()
	e.recoverMu.Unlock()
	e.log.Warn("traefik self-heal recovery", "level", level, "action", action)
	_ = e.st.AddAudit(ctx, &store.AuditEntry{
		UserEmail: "system", Action: "traefik.recovery",
		Target: fmt.Sprintf("level-%d", level), Detail: action,
	})
	e.notifier.Notify(ctx, "error", "Traefik auto-recovery",
		fmt.Sprintf("Crash-loop detected — %s (escalation level %d).", action, level))
}

// RecoveryState is the self-heal status surfaced on /api/health.
type RecoveryState struct {
	Level      int       `json:"level"`
	LastAction string    `json:"lastAction,omitempty"`
	At         time.Time `json:"at,omitempty"`
}

// RecoveryState returns the current self-heal escalation state.
func (e *Engine) RecoveryState() RecoveryState {
	e.recoverMu.Lock()
	defer e.recoverMu.Unlock()
	return RecoveryState{Level: e.recoverLevel, LastAction: e.lastRecovery, At: e.lastRecoveryAt}
}

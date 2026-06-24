package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/suckharder/xgress/internal/secmetrics"
	"github.com/suckharder/xgress/internal/store"
)

// Auto-ban (fail2ban-style) settings keys and defaults. The feature is OFF by
// default: enabling it requires no Traefik restart (the ban is enforced by a
// hot-reloaded high-priority deny router), so it is purely opt-in.
const (
	keyBanEnabled   = "ban.enabled"     // "true" to enable auto-ban (default false)
	keyBanThreshold = "ban.threshold"   // WAF blocks within the window before banning
	keyBanWindowSec = "ban.windowSec"   // sliding window length in seconds
	keyBanDuration  = "ban.durationSec" // how long an auto-ban lasts

	defBanThreshold = 5
	defBanWindowSec = 600  // 10 minutes
	defBanDuration  = 3600 // 1 hour
)

// BanConfig is the resolved auto-ban configuration.
type BanConfig struct {
	Enabled     bool `json:"enabled"`
	Threshold   int  `json:"threshold"`
	WindowSec   int  `json:"windowSec"`
	DurationSec int  `json:"durationSec"`
}

// loadBanConfig reads the auto-ban settings from the store (4 reads).
func (e *Engine) loadBanConfig(ctx context.Context) BanConfig {
	return BanConfig{
		Enabled:     e.settingBool(ctx, keyBanEnabled, false),
		Threshold:   e.settingInt(ctx, keyBanThreshold, defBanThreshold),
		WindowSec:   e.settingInt(ctx, keyBanWindowSec, defBanWindowSec),
		DurationSec: e.settingInt(ctx, keyBanDuration, defBanDuration),
	}
}

// BanConfig returns the current auto-ban settings, served from an in-memory cache
// so the hot WAF-block path (onWAFEvent) doesn't issue 4 DB reads per blocked
// request. The cache is the source of truth within the process: SetBanConfig is the
// only writer and refreshes it; the first read lazily loads it. (P1-7)
func (e *Engine) BanConfig(ctx context.Context) BanConfig {
	if c := e.banConfig.Load(); c != nil {
		return *c
	}
	c := e.loadBanConfig(ctx)
	e.banConfig.Store(&c)
	return c
}

// SetBanConfig persists the auto-ban settings.
func (e *Engine) SetBanConfig(ctx context.Context, c BanConfig) error {
	if c.Threshold < 1 {
		c.Threshold = defBanThreshold
	}
	if c.WindowSec < 1 {
		c.WindowSec = defBanWindowSec
	}
	if c.DurationSec < 0 {
		c.DurationSec = defBanDuration
	}
	for _, kv := range []struct{ k, v string }{
		{keyBanEnabled, boolStr(c.Enabled)},
		{keyBanThreshold, fmt.Sprint(c.Threshold)},
		{keyBanWindowSec, fmt.Sprint(c.WindowSec)},
		{keyBanDuration, fmt.Sprint(c.DurationSec)},
	} {
		if err := e.st.SetSetting(ctx, kv.k, kv.v); err != nil {
			e.banConfig.Store(nil) // partial write: invalidate so the next read reloads from DB
			return err
		}
	}
	e.banConfig.Store(&c) // refresh the cache so onWAFEvent sees the change with no DB read
	return nil
}

// onWAFEvent is invoked (off the request path) for every WAF detection. When
// auto-ban is enabled it records the block in a per-IP sliding window and bans
// the IP once it crosses the threshold within the window.
func (e *Engine) onWAFEvent(ev secmetrics.Event) {
	if !ev.Blocked || ev.ClientIP == "" {
		return
	}
	ctx := context.Background()
	cfg := e.BanConfig(ctx)
	if !cfg.Enabled {
		return
	}
	ip := ev.ClientIP
	now := time.Now()
	window := time.Duration(cfg.WindowSec) * time.Second

	e.banMu.Lock()
	hits := append(e.banHits[ip], now)
	// Drop timestamps outside the window.
	cut := now.Add(-window)
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	e.banHits[ip] = kept
	count := len(kept)
	over := count >= cfg.Threshold
	if over {
		delete(e.banHits, ip) // reset window after banning
	}
	e.banMu.Unlock()

	if !over {
		return
	}
	// Already actively banned? Avoid re-banning / redundant reloads.
	if banned, _ := e.st.IsActivelyBanned(ctx, ip); banned {
		return
	}
	exp := now.Add(time.Duration(cfg.DurationSec) * time.Second)
	var expPtr *time.Time
	if cfg.DurationSec > 0 {
		expPtr = &exp
	}
	b := &store.Ban{
		IP:        ip,
		Reason:    fmt.Sprintf("auto: %d WAF blocks in %ds", count, cfg.WindowSec),
		Manual:    false,
		Hits:      count,
		ExpiresAt: expPtr,
	}
	if err := e.st.AddBan(ctx, b); err != nil {
		e.log.Error("auto-ban: add ban", "ip", ip, "err", err)
		return
	}
	e.log.Warn("auto-banned IP", "ip", ip, "hits", count, "windowSec", cfg.WindowSec, "durationSec", cfg.DurationSec)
	// Coalesce reloads: a flood of bans triggers at most one reload per debounce
	// window (see banReloadLoop), not one full re-render per banned IP.
	e.scheduleBanReload()
	e.notifier.Notify(ctx, "warning", "IP auto-banned",
		fmt.Sprintf("%s was banned after %d WAF blocks in %ds.", ip, count, cfg.WindowSec))
}

// scheduleBanReload requests a debounced reload after an auto-ban. The send is
// non-blocking; banReloadLoop (started by StartBackground) coalesces signals so a
// burst of bans collapses into one reload. When the loop isn't running (e.g. in a
// unit test that doesn't call StartBackground) the signal is simply buffered/dropped
// and the caller is expected to reload explicitly.
func (e *Engine) scheduleBanReload() {
	select {
	case e.banReload <- struct{}{}:
	default: // a reload is already pending — coalesce
	}
}

// banReloadLoop performs the debounced auto-ban reloads.
func (e *Engine) banReloadLoop(ctx context.Context) {
	const debounce = 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.banReload:
			t := time.NewTimer(debounce) // coalesce further bans landing in this window
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
			if _, err := e.Reload(ctx); err != nil {
				e.log.Error("auto-ban: debounced reload", "err", err)
			}
		}
	}
}

// ListBans returns currently active bans.
func (e *Engine) ListBans(ctx context.Context) ([]*store.Ban, error) {
	return e.st.ListActiveBans(ctx)
}

// AddManualBan bans an IP/CIDR for durationSec seconds (0 = permanent), then
// hot-reloads the deny router.
func (e *Engine) AddManualBan(ctx context.Context, ip, reason string, durationSec int) error {
	var expPtr *time.Time
	if durationSec > 0 {
		exp := time.Now().Add(time.Duration(durationSec) * time.Second)
		expPtr = &exp
	}
	if reason == "" {
		reason = "manual"
	}
	b := &store.Ban{IP: ip, Reason: reason, Manual: true, ExpiresAt: expPtr}
	if err := e.st.AddBan(ctx, b); err != nil {
		return err
	}
	e.log.Info("manually banned IP", "ip", ip, "durationSec", durationSec)
	_, err := e.Reload(ctx)
	return err
}

// RemoveBan unbans an IP/CIDR and hot-reloads the deny router.
func (e *Engine) RemoveBan(ctx context.Context, ip string) error {
	if err := e.st.DeleteBan(ctx, ip); err != nil {
		return err
	}
	e.banMu.Lock()
	delete(e.banHits, ip)
	e.banMu.Unlock()
	e.log.Info("unbanned IP", "ip", ip)
	_, err := e.Reload(ctx)
	return err
}

// banPruneLoop periodically removes expired bans and, when any were removed,
// hot-reloads so the deny router no longer lists them.
func (e *Engine) banPruneLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.sweepBanHits(ctx) // evict stale per-IP WAF-hit windows (bounded memory)
			n, err := e.st.PruneExpiredBans(ctx)
			if err != nil {
				e.log.Error("ban prune", "err", err)
				continue
			}
			if n > 0 {
				e.log.Info("pruned expired bans", "count", n)
				if _, err := e.Reload(ctx); err != nil {
					e.log.Error("ban prune: reload", "err", err)
				}
			}
		}
	}
}

// sweepBanHits drops per-IP sliding windows whose newest WAF block is older than
// the auto-ban window, so the banHits map can't grow unbounded with the cardinality
// of attacking IPs that never cross the threshold.
func (e *Engine) sweepBanHits(ctx context.Context) {
	win := time.Duration(e.BanConfig(ctx).WindowSec) * time.Second
	cut := time.Now().Add(-win)
	e.banMu.Lock()
	for ip, ts := range e.banHits {
		if len(ts) == 0 || ts[len(ts)-1].Before(cut) {
			delete(e.banHits, ip)
		}
	}
	e.banMu.Unlock()
}

func (e *Engine) settingInt(ctx context.Context, key string, def int) int {
	v, err := e.st.GetSetting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

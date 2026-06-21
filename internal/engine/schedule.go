package engine

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// StartScheduler runs the host enable/disable scheduler (Round 4a). It evaluates
// 5-field cron schedules once per minute and flips the matching hosts' enabled
// flag, reloading once if anything changed.
//
// Recovery is PER-ITERATION (recoverGuard inside the loop): a panic in cron parsing
// or a store call is logged but the loop keeps running, so the scheduler — and PID 1,
// which also supervises Traefik — stays up. Wrapping the whole loop in a single
// recover would instead kill the scheduler permanently on the first panic.
func (e *Engine) StartScheduler(ctx context.Context) {
	go func() {
		for {
			// Sleep to the next minute boundary, then evaluate.
			now := time.Now()
			next := now.Truncate(time.Minute).Add(time.Minute)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Until(next)):
			}
			e.recoverGuard("scheduler tick", func() { e.runSchedules(ctx, time.Now()) })
		}
	}()
}

func (e *Engine) runSchedules(ctx context.Context, now time.Time) {
	schedules, err := e.st.ListSchedules(ctx, "")
	if err != nil {
		return
	}
	changed := false
	for _, sc := range schedules {
		if !cronMatches(sc.Cron, now) {
			continue
		}
		h, err := e.st.GetHost(ctx, sc.HostID)
		if err != nil {
			continue
		}
		want := sc.Action == "enable"
		if h.Enabled == want {
			continue
		}
		h.Enabled = want
		if err := e.st.UpdateHost(ctx, h); err == nil {
			e.log.Info("schedule applied", "host", h.ID, "action", sc.Action)
			changed = true
		}
	}
	if changed {
		if _, err := e.Reload(ctx); err != nil {
			e.log.Error("reload after schedule", "err", err)
		}
	}
}

// cronMatches reports whether a 5-field cron expression (min hour dom month dow)
// matches t. Supports '*', numbers, ranges (a-b), steps (*/n, a-b/n), and lists.
func cronMatches(expr string, t time.Time) bool {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	return matchField(fields[0], t.Minute(), 0, 59) &&
		matchField(fields[1], t.Hour(), 0, 23) &&
		matchField(fields[2], t.Day(), 1, 31) &&
		matchField(fields[3], int(t.Month()), 1, 12) &&
		matchField(fields[4], int(t.Weekday()), 0, 6)
}

func matchField(field string, val, min, max int) bool {
	for _, part := range strings.Split(field, ",") {
		if matchPart(strings.TrimSpace(part), val, min, max) {
			return true
		}
	}
	return false
}

func matchPart(part string, val, min, max int) bool {
	step := 1
	if i := strings.Index(part, "/"); i >= 0 {
		step, _ = strconv.Atoi(part[i+1:])
		if step <= 0 {
			step = 1
		}
		part = part[:i]
	}
	lo, hi := min, max
	switch {
	case part == "*" || part == "":
		// full range
	case strings.Contains(part, "-"):
		b := strings.SplitN(part, "-", 2)
		lo, _ = strconv.Atoi(b[0])
		hi, _ = strconv.Atoi(b[1])
	default:
		n, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		lo, hi = n, n
	}
	if val < lo || val > hi {
		return false
	}
	return (val-lo)%step == 0
}

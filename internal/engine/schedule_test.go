package engine

import (
	"testing"
	"time"
)

func TestCronMatches(t *testing.T) {
	// Mon 2026-06-08 09:30.
	mon0930 := time.Date(2026, 6, 8, 9, 30, 0, 0, time.UTC)
	cases := []struct {
		expr string
		want bool
	}{
		{"30 9 * * *", true},
		{"* * * * *", true},
		{"0 9 * * *", false},
		{"30 9 * * 1", true},    // Monday
		{"30 9 * * 0", false},   // Sunday
		{"30 9 * * 1-5", true},  // weekdays
		{"30 9 8 6 *", true},    // day 8, June
		{"*/15 * * * *", true},  // 30 is a multiple of 15
		{"*/20 * * * *", false}, // 30 not a multiple of 20
		{"0,30 9 * * *", true},  // list
		{"bad expr", false},
	}
	for _, c := range cases {
		if got := cronMatches(c.expr, mon0930); got != c.want {
			t.Errorf("cronMatches(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

// TestRecoverGuardContainsPanic proves the scheduler's per-iteration recovery
// semantics: a panicking tick is contained (does not propagate) so the loop's
// next iteration still runs — i.e. one bad schedule can't kill the scheduler or
// crash PID 1.
func TestRecoverGuardContainsPanic(t *testing.T) {
	e := newTestEngine(t)
	e.recoverGuard("test-panic", func() { panic("boom") }) // must not propagate
	ran := false
	e.recoverGuard("test-ok", func() { ran = true }) // the loop keeps going
	if !ran {
		t.Fatal("recoverGuard did not return normally after a recovered panic")
	}
}

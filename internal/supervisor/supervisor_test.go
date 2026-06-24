package supervisor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The supervisor execs a real child process, so these tests use the canonical Go
// re-exec pattern: TestMain re-enters this same test binary as the "fake traefik"
// when XGRESS_SUP_HELPER=1. The supervisor invokes the binary with a fixed
// `--configFile=<path>` argument (it can't pass extra flags), so the helper is
// selected via the inherited environment (set by t.Setenv) rather than args, and
// any per-test data (e.g. a crash marker) is smuggled through the configFile path.
func TestMain(m *testing.M) {
	if os.Getenv("XGRESS_SUP_HELPER") == "1" {
		runFakeTraefik()
		return // unreachable; runFakeTraefik always exits
	}
	os.Exit(m.Run())
}

// runFakeTraefik impersonates the Traefik child process. Its behavior is chosen by
// XGRESS_SUP_MODE; the marker path (crash-once mode) is read from --configFile.
func runFakeTraefik() {
	mode := os.Getenv("XGRESS_SUP_MODE")
	cfgFile := ""
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "--configFile=") {
			cfgFile = strings.TrimPrefix(a, "--configFile=")
		}
	}

	switch mode {
	case "emit":
		// One JSON line (level + message + error are merged by the supervisor), one
		// JSON line on stderr, and one non-JSON line (falls back to level=info, raw).
		fmt.Fprintln(os.Stdout, `{"level":"warn","message":"hello","error":"boom"}`)
		fmt.Fprintln(os.Stderr, `{"level":"error","msg":"on stderr"}`)
		fmt.Fprintln(os.Stdout, `not json at all`)
		sleepForever()
	case "ignore-term":
		// Catch (and ignore) SIGTERM so the supervisor must fall back to SIGKILL.
		// Announce readiness only AFTER the handler is installed, so the test never
		// sends SIGTERM during the startup window where the default disposition
		// (terminate) would still apply.
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM)
		fmt.Fprintln(os.Stdout, `{"level":"info","message":"ready"}`)
		sleepForever()
	case "crash-once":
		// First invocation exits non-zero (unexpected crash); the watchdog respawns
		// us, and the marker makes the second invocation run normally.
		if cfgFile != "" {
			if _, err := os.Stat(cfgFile); err == nil {
				fmt.Fprintln(os.Stdout, `{"level":"info","message":"respawned-ok"}`)
				sleepForever()
			}
			_ = os.WriteFile(cfgFile, []byte("x"), 0o600)
		}
		os.Exit(3)
	case "crash-always":
		// Every invocation exits non-zero immediately — drives the crash-loop guard.
		os.Exit(7)
	case "spam":
		for i := 0; i < 1500; i++ {
			fmt.Fprintf(os.Stdout, "{\"level\":\"info\",\"message\":\"line-%d\"}\n", i)
		}
		fmt.Fprintln(os.Stdout, `{"level":"info","message":"DONE"}`)
		sleepForever()
	default:
		// Plain long-lived process that dies on SIGTERM by default (no handler).
		sleepForever()
	}
	os.Exit(0)
}

// sleepForever blocks without a bare select{} (which Go would flag as a deadlock).
func sleepForever() { time.Sleep(60 * time.Second) }

// helperOpts builds Options that re-exec this test binary as the fake child.
func helperOpts(t *testing.T, mode string, drain time.Duration) Options {
	t.Helper()
	t.Setenv("XGRESS_SUP_HELPER", "1")
	t.Setenv("XGRESS_SUP_MODE", mode)
	return Options{
		Binary:       os.Args[0],
		ConfigFile:   t.TempDir() + "/cfg",
		Managed:      true,
		RestartDrain: drain,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// startManaged starts a managed supervisor and registers teardown that cancels the
// watchdog context and stops the child, so no respawn loop leaks past the test.
func startManaged(t *testing.T, opts Options) (*Supervisor, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := New(opts)
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = s.Stop()
	})
	return s, ctx
}

func waitState(t *testing.T, s *Supervisor, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.Status().State == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state never reached %q (last %q)", want, s.Status().State)
}

func TestUnmanagedIsInert(t *testing.T) {
	s := New(Options{Managed: false, Logger: discard()})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start (unmanaged) should be a no-op: %v", err)
	}
	st := s.Status()
	if st.State != StateExternal {
		t.Errorf("state = %q, want %q", st.State, StateExternal)
	}
	if st.Managed {
		t.Error("Managed should be false")
	}
	if err := s.Restart(context.Background()); err == nil {
		t.Error("Restart should error when traefik is external")
	}
	if err := s.Stop(); err != nil {
		t.Errorf("Stop (unmanaged) should be nil: %v", err)
	}
}

// P0-3: a panicking log observer must not kill the consume goroutine — otherwise
// the engine's fatal-crash detector dying would silently disable crash detection.
func TestConsumeIsolatesPanickingObserver(t *testing.T) {
	s := New(Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	var goodRan int32
	s.AddLogObserver(func(LogLine) { panic("observer boom") })
	s.AddLogObserver(func(LogLine) { atomic.AddInt32(&goodRan, 1) })

	// consume reads to EOF; without panic isolation the first observer's panic would
	// unwind consume and the second observer would never run (and the goroutine die).
	s.consume(strings.NewReader("line one\nline two\n"))

	if n := atomic.LoadInt32(&goodRan); n != 2 {
		t.Errorf("non-panicking observer ran %d times, want 2 (panicking observer must be isolated)", n)
	}
}

// P3-12: a panicking OnCrashLoop callback must not crash PID 1. fireCrashLoop runs
// it in a panic-isolated goroutine; without that, the unrecovered panic would abort
// the whole process (and this test binary).
func TestCrashLoopCallbackPanicIsolated(t *testing.T) {
	fired := make(chan struct{})
	s := New(Options{
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnCrashLoop: func() { close(fired); panic("callback boom") },
	})
	s.TripCrashLoop()
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OnCrashLoop never fired")
	}
	// Let the goroutine's deferred recover run; if the panic weren't isolated the
	// process would already be gone.
	time.Sleep(50 * time.Millisecond)
}

func TestSpawnCapturesLogsAndObservers(t *testing.T) {
	opts := helperOpts(t, "emit", 3*time.Second)

	// Register the observer before Start so it sees the lines as they're consumed.
	got := make(chan LogLine, 16)
	s := New(opts)
	s.AddLogObserver(func(ll LogLine) { got <- ll })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = s.Stop() })
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	waitState(t, s, StateRunning, 3*time.Second)
	if pid := s.Status().Pid; pid <= 0 {
		t.Errorf("running pid = %d, want > 0", pid)
	}

	// Observer must receive the merged "hello: boom" warn line.
	if !awaitLine(t, got, func(ll LogLine) bool {
		return ll.Level == "warn" && ll.Message == "hello: boom"
	}) {
		t.Error("observer never saw the merged JSON warn line")
	}

	// The raw line is emitted AFTER the warn line, so wait for the observer to
	// see it before inspecting the ring buffer. consume() calls appendLog before
	// notifying observers (same goroutine), so once the observer has the line it
	// is guaranteed to already be in the ring — this avoids a CI flake where the
	// buffer was read before the raw line had been consumed.
	if !awaitLine(t, got, func(ll LogLine) bool {
		return ll.Level == "info" && ll.Message == "not json at all"
	}) {
		t.Error("observer never saw the non-JSON raw line")
	}

	// The ring buffer must hold both the JSON and the non-JSON (raw, level=info) lines.
	var sawRaw bool
	for _, ll := range s.Logs(0) {
		if ll.Level == "info" && ll.Message == "not json at all" {
			sawRaw = true
		}
	}
	if !sawRaw {
		t.Error("non-JSON line not captured as level=info raw message")
	}
}

func TestGracefulStopHonorsSIGTERM(t *testing.T) {
	// The default helper has no SIGTERM handler, so it dies promptly — Stop must
	// return well before the (long) drain elapses.
	opts := helperOpts(t, "default", 5*time.Second)
	s, _ := startManaged(t, opts)
	waitState(t, s, StateRunning, 3*time.Second)

	start := time.Now()
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Errorf("Stop took %v; SIGTERM should have ended it well before the 5s drain", elapsed)
	}
	if st := s.Status().State; st != StateStopped {
		t.Errorf("state after stop = %q, want %q", st, StateStopped)
	}
}

func TestGracefulStopFallsBackToSIGKILL(t *testing.T) {
	// This helper ignores SIGTERM, so Stop must wait the drain, then SIGKILL.
	drain := 400 * time.Millisecond
	opts := helperOpts(t, "ignore-term", drain)
	s, _ := startManaged(t, opts)
	waitState(t, s, StateRunning, 3*time.Second)

	// Wait until the child has installed its SIGTERM handler (avoids the startup race
	// where the default disposition would terminate it before the handler is live).
	if !awaitFunc(t, 3*time.Second, func() bool {
		for _, ll := range s.Logs(0) {
			if ll.Message == "ready" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("ignore-term child never became ready")
	}

	start := time.Now()
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < drain {
		t.Errorf("Stop returned in %v, want >= drain %v (SIGKILL path not taken)", elapsed, drain)
	}
	if st := s.Status().State; st != StateStopped {
		t.Errorf("state after kill = %q, want %q", st, StateStopped)
	}
}

func TestRestartReplacesProcess(t *testing.T) {
	opts := helperOpts(t, "default", 3*time.Second)
	s, ctx := startManaged(t, opts)
	waitState(t, s, StateRunning, 3*time.Second)
	pid1 := s.Status().Pid

	if err := s.Restart(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	waitState(t, s, StateRunning, 3*time.Second)
	pid2 := s.Status().Pid
	if pid2 == 0 || pid2 == pid1 {
		t.Errorf("restart did not replace the process: pid1=%d pid2=%d", pid1, pid2)
	}
}

func TestWatchdogRespawnsAfterCrash(t *testing.T) {
	// crash-once exits non-zero on first run; the watchdog must respawn it, and the
	// marker (the configFile path) makes the second run come up healthy.
	opts := helperOpts(t, "crash-once", 3*time.Second)
	s, _ := startManaged(t, opts)

	// The watchdog sleeps ~1s before respawning; allow generous slack.
	waitState(t, s, StateRunning, 6*time.Second)

	// And the healthy respawn emitted its marker log line.
	if !awaitFunc(t, 3*time.Second, func() bool {
		for _, ll := range s.Logs(0) {
			if ll.Message == "respawned-ok" {
				return true
			}
		}
		return false
	}) {
		t.Error("respawned child never logged 'respawned-ok'")
	}
}

func TestCrashLoopGuardHaltsRespawnAndFiresCallbackOnce(t *testing.T) {
	var tripped int32
	opts := helperOpts(t, "crash-always", time.Second)
	opts.OnCrashLoop = func() { atomic.AddInt32(&tripped, 1) }
	s, _ := startManaged(t, opts)

	// 3 unexpected exits within 10s (the watchdog waits ~1s between respawns) trips
	// the guard, which halts auto-respawn and fires the callback exactly once.
	if !awaitFunc(t, 14*time.Second, func() bool { return s.Status().CrashLoop }) {
		t.Fatal("crash-loop guard did not trip")
	}
	st := s.Status()
	if st.Restarts < crashThreshold {
		t.Errorf("restarts = %d, want >= %d", st.Restarts, crashThreshold)
	}
	if got := atomic.LoadInt32(&tripped); got != 1 {
		t.Errorf("OnCrashLoop fired %d times, want 1", got)
	}
	// Confirm respawning has actually stopped (no further crashes/callbacks).
	time.Sleep(1500 * time.Millisecond)
	if got := atomic.LoadInt32(&tripped); got != 1 {
		t.Errorf("OnCrashLoop fired again after trip (now %d) — respawn was not halted", got)
	}
}

func TestTripCrashLoopIsSingleFlight(t *testing.T) {
	var tripped int32
	opts := helperOpts(t, "longlived", time.Second) // default mode: stays up
	opts.OnCrashLoop = func() { atomic.AddInt32(&tripped, 1) }
	s, _ := startManaged(t, opts)
	waitState(t, s, StateRunning, 3*time.Second)

	s.TripCrashLoop()
	s.TripCrashLoop() // idempotent — a burst of fatal log lines must fire once
	if !awaitFunc(t, 2*time.Second, func() bool { return atomic.LoadInt32(&tripped) == 1 }) {
		t.Fatalf("TripCrashLoop should fire OnCrashLoop once, got %d", atomic.LoadInt32(&tripped))
	}
	if !s.Status().CrashLoop {
		t.Error("TripCrashLoop should set CrashLoop status")
	}
}

func TestRingBufferIsBounded(t *testing.T) {
	opts := helperOpts(t, "spam", 3*time.Second)
	s, _ := startManaged(t, opts)

	// Wait until the sentinel (last emitted line) has been consumed. NOTE: Logs()
	// returns the ring in PHYSICAL slot order, so after wraparound the sentinel is
	// NOT the last element — it lands at slot 1500%1000. We therefore scan the whole
	// ring for it rather than relying on ordering (a known ring quirk).
	if !awaitFunc(t, 8*time.Second, func() bool {
		for _, ll := range s.Logs(0) {
			if ll.Message == "DONE" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("sentinel DONE line never arrived")
	}

	if n := len(s.Logs(0)); n != 1000 {
		t.Errorf("ring buffer holds %d lines, want it capped at 1000", n)
	}
	if n := len(s.Logs(10)); n != 10 {
		t.Errorf("Logs(10) returned %d lines, want 10", n)
	}
}

// --- helpers ---------------------------------------------------------------

func discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func awaitLine(t *testing.T, ch <-chan LogLine, pred func(LogLine) bool) bool {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case ll := <-ch:
			if pred(ll) {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

func awaitFunc(t *testing.T, timeout time.Duration, fn func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

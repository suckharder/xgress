// Package supervisor owns the Traefik child process in the single-container
// deployment. xgress runs as PID 1 and Traefik is its child, which is what makes
// graceful restarts, log capture, and health checks clean: a static-config
// change restarts only the Traefik process — the container, the admin UI, and
// the API all stay up. (In the external-Traefik deployment the supervisor is
// disabled and xgress only writes the static file for the external Traefik.)
package supervisor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// State is the supervised process lifecycle state.
type State string

const (
	StateStopped  State = "stopped"
	StateRunning  State = "running"
	StateRestart  State = "restarting"
	StateCrashed  State = "crashed"
	StateExternal State = "external" // not managed by xgress
)

// LogLine is a captured Traefik log entry kept in a ring buffer for the UI.
type LogLine struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Raw     string    `json:"raw"`
}

// Options configures the supervisor.
type Options struct {
	Binary       string        // path to traefik
	ConfigFile   string        // path to static config (traefik.yml)
	WorkDir      string        // Traefik's working dir (Traefik writes plugins-storage here)
	Managed      bool          // false => external Traefik, supervisor is inert
	RestartDrain time.Duration // grace period before SIGKILL on restart/stop
	Logger       *slog.Logger
}

// Supervisor manages a single Traefik process.
type Supervisor struct {
	opts Options
	log  *slog.Logger

	mu        sync.Mutex
	cmd       *exec.Cmd
	state     State
	startedAt time.Time
	lastExit  error
	wantStop  bool

	// log ring buffer
	ring   []LogLine
	ringMu sync.Mutex
	ringN  int

	// log observers (e.g. security-metrics collector)
	obsMu     sync.RWMutex
	observers []func(LogLine)

	exited chan struct{}
}

// New constructs a supervisor.
func New(opts Options) *Supervisor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.RestartDrain <= 0 {
		opts.RestartDrain = 10 * time.Second
	}
	s := &Supervisor{opts: opts, log: opts.Logger, state: StateStopped, ring: make([]LogLine, 0, 512)}
	if !opts.Managed {
		s.state = StateExternal
	}
	return s
}

// Start launches Traefik (no-op when unmanaged). It also starts a watchdog that
// restarts the process if it crashes unexpectedly.
func (s *Supervisor) Start(ctx context.Context) error {
	if !s.opts.Managed {
		s.log.Info("traefik is external; supervisor inert")
		return nil
	}
	return s.spawn(ctx)
}

func (s *Supervisor) spawn(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spawnLocked(ctx)
}

func (s *Supervisor) spawnLocked(ctx context.Context) error {
	cmd := exec.Command(s.opts.Binary, "--configFile="+s.opts.ConfigFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Run Traefik from the data dir so its plugins-storage/ (downloaded plugins)
	// lands on the persisted volume and survives restarts.
	if s.opts.WorkDir != "" {
		cmd.Dir = s.opts.WorkDir
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		s.state = StateCrashed
		s.lastExit = err
		return err
	}
	s.cmd = cmd
	s.state = StateRunning
	s.startedAt = time.Now()
	s.wantStop = false
	s.exited = make(chan struct{})

	go s.consume(stdout)
	go s.consume(stderr)

	exited := s.exited
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.lastExit = err
		stopWanted := s.wantStop
		if stopWanted {
			s.state = StateStopped
		} else {
			s.state = StateCrashed
		}
		s.mu.Unlock()
		close(exited)

		if !stopWanted && ctx.Err() == nil {
			s.log.Error("traefik exited unexpectedly; restarting", "err", err)
			time.Sleep(time.Second)
			if ctx.Err() == nil {
				_ = s.spawn(ctx)
			}
		}
	}()

	s.log.Info("traefik started", "pid", cmd.Process.Pid, "config", s.opts.ConfigFile)
	return nil
}

// Restart performs a graceful restart: SIGTERM, wait up to RestartDrain, then
// SIGKILL if needed, then re-spawn with the (possibly changed) static config.
// The container is never affected.
func (s *Supervisor) Restart(ctx context.Context) error {
	if !s.opts.Managed {
		return errors.New("cannot restart: traefik is external")
	}
	s.mu.Lock()
	s.state = StateRestart
	s.mu.Unlock()
	if err := s.stopProcess(); err != nil {
		s.log.Warn("error stopping traefik during restart", "err", err)
	}
	return s.spawn(ctx)
}

// Stop terminates Traefik for shutdown.
func (s *Supervisor) Stop() error {
	if !s.opts.Managed {
		return nil
	}
	return s.stopProcess()
}

func (s *Supervisor) stopProcess() error {
	s.mu.Lock()
	cmd := s.cmd
	exited := s.exited
	s.wantStop = true
	s.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	if exited == nil {
		return nil
	}
	select {
	case <-exited:
		return nil
	case <-time.After(s.opts.RestartDrain):
		s.log.Warn("traefik did not exit in time; killing")
		_ = cmd.Process.Kill()
		<-exited
		return nil
	}
}

// consume reads Traefik's (JSON) log stream into the ring buffer.
func (s *Supervisor) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		ll := LogLine{At: time.Now(), Raw: line, Message: line, Level: "info"}
		var parsed struct {
			Level   string `json:"level"`
			Message string `json:"message"`
			Msg     string `json:"msg"`
			Error   string `json:"error"`
		}
		if json.Unmarshal([]byte(line), &parsed) == nil {
			if parsed.Level != "" {
				ll.Level = parsed.Level
			}
			if parsed.Message != "" {
				ll.Message = parsed.Message
			} else if parsed.Msg != "" {
				ll.Message = parsed.Msg
			}
			if parsed.Error != "" {
				ll.Message += ": " + parsed.Error
			}
		}
		s.appendLog(ll)
		s.obsMu.RLock()
		obs := s.observers
		s.obsMu.RUnlock()
		for _, fn := range obs {
			fn(ll)
		}
	}
}

// AddLogObserver registers a callback invoked for every captured Traefik log
// line (used by the security-metrics collector to parse WAF events live).
func (s *Supervisor) AddLogObserver(fn func(LogLine)) {
	s.obsMu.Lock()
	s.observers = append(s.observers, fn)
	s.obsMu.Unlock()
}

func (s *Supervisor) appendLog(ll LogLine) {
	const max = 1000
	s.ringMu.Lock()
	if len(s.ring) < max {
		s.ring = append(s.ring, ll)
	} else {
		s.ring[s.ringN%max] = ll
	}
	s.ringN++
	s.ringMu.Unlock()
}

// Logs returns up to n most recent log lines (newest last).
func (s *Supervisor) Logs(n int) []LogLine {
	s.ringMu.Lock()
	defer s.ringMu.Unlock()
	out := make([]LogLine, len(s.ring))
	copy(out, s.ring)
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// Status reports the current lifecycle state.
type Status struct {
	State     State     `json:"state"`
	Pid       int       `json:"pid"`
	StartedAt time.Time `json:"startedAt"`
	LastError string    `json:"lastError,omitempty"`
	Managed   bool      `json:"managed"`
}

// Status returns a snapshot of the supervised process state.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{State: s.state, StartedAt: s.startedAt, Managed: s.opts.Managed}
	if s.cmd != nil && s.cmd.Process != nil {
		st.Pid = s.cmd.Process.Pid
	}
	if s.lastExit != nil {
		st.LastError = s.lastExit.Error()
	}
	return st
}

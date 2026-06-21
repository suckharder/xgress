//go:build integration

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/traefikcfg"
)

// nativeEnv runs Traefik as a native child process on the host (macOS/Linux),
// reaching the test's loopback servers directly. No Docker required.
type nativeEnv struct{}

// reachable is the identity: a native process shares the host's loopback.
func (nativeEnv) reachable(host string) string { return host }

func (nativeEnv) run(t *testing.T, params traefikcfg.StaticParams) (traefikEndpoints, func()) {
	t.Helper()
	bin := ensureTraefik(t)

	yamlBytes, err := traefikcfg.RenderStatic(params)
	if err != nil {
		t.Fatalf("render static config: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "traefik.yml")
	if err := os.WriteFile(cfgPath, yamlBytes, 0o644); err != nil {
		t.Fatalf("write static config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "--configFile="+cfgPath)
	logs := &syncBuffer{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start traefik: %v", err)
	}

	stop := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM) // graceful drain first
		}
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cancel() // escalate to SIGKILL via the context
			<-done
		}
		cancel()
	}

	eps := traefikEndpoints{
		web:       fmt.Sprintf("http://127.0.0.1:%d", params.HTTPPort),
		websecure: fmt.Sprintf("127.0.0.1:%d", params.HTTPSPort),
		api:       "http://" + params.APIListen,
		logs:      logs,
	}

	// Readiness: the static config wires Traefik's ping handler to the HTTP
	// entrypoint, so a 200 there means the process is up and serving.
	if err := waitReady(eps.web+"/ping", 20*time.Second); err != nil {
		stop()
		t.Fatalf("traefik did not become ready: %v\n--- traefik logs ---\n%s", err, logs.String())
	}
	return eps, stop
}

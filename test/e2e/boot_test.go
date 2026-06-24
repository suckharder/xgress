//go:build integration

// Boot tier: exercises cmd/xgress's run() end-to-end against the real binary. run() is
// otherwise covered only indirectly (Tier C, via Docker). Here we build the binary
// with -cover, run it natively in the unmanaged-Traefik mode (so no Traefik process
// is needed — the supervisor is inert), prove all three HTTP servers come up and the
// store-write path works (first-run setup), then SIGTERM it and assert a clean
// (exit 0) graceful shutdown. With GOCOVERDIR set, the binary emits coverage for run()
// and everything it wires together.
package e2e

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCmdBootAndGracefulShutdown(t *testing.T) {
	bin := buildInstrumentedXgress(t)

	dataDir := t.TempDir()
	covDir := t.TempDir()
	ports := freePorts(t, 3)
	adminAddr := fmt.Sprintf("127.0.0.1:%d", ports[0])
	providerAddr := fmt.Sprintf("127.0.0.1:%d", ports[1])
	edgeAddr := fmt.Sprintf("127.0.0.1:%d", ports[2])

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"XGRESS_DATA_DIR="+dataDir,
		"XGRESS_DB_DRIVER=sqlite",
		"XGRESS_TRAEFIK_MANAGED=false", // supervisor inert → no Traefik binary required
		"XGRESS_DEV=true",              // allow plain-HTTP admin cookies
		"XGRESS_ADMIN_LISTEN="+adminAddr,
		"XGRESS_PROVIDER_LISTEN="+providerAddr,
		"XGRESS_EDGE_LISTEN="+edgeAddr,
		"XGRESS_EDGE_TOKEN=boot-edge-token", // known token so the test can reach the edge
		"GOCOVERDIR="+covDir,
	)
	var logs syncBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start xgress: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	adminBase := "http://" + adminAddr
	client := &http.Client{Timeout: 2 * time.Second}

	// 1) Admin server up: /api/setup is open and returns 200 before first-run setup.
	if err := waitReadyWith(client, adminBase+"/api/setup", 30*time.Second); err != nil {
		t.Fatalf("admin server never came up: %v\n--- logs ---\n%s", err, logs.String())
	}

	// 2) Edge server up + token gate live: an untokened request is rejected (403).
	if resp, err := client.Get("http://" + edgeAddr + "/"); err != nil {
		t.Errorf("edge server not reachable: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("edge GET = %d, want 403 (token gate)", resp.StatusCode)
		}
	}

	// 3) Provider/challenge server up: the ACME-challenge path is open and answers
	//    (404 for an unknown token) — i.e. the provider mux is serving.
	if resp, err := client.Get("http://" + providerAddr + "/.well-known/acme-challenge/nope"); err != nil {
		t.Errorf("provider server not reachable: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("provider challenge GET = %d, want 404", resp.StatusCode)
		}
	}

	// 4) Store-write path through run(): first-run setup creates the admin user.
	body := `{"email":"admin@boot.test","name":"Admin","password":"password123"}`
	resp, err := client.Post(adminBase+"/api/setup", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/setup: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup = %d, want 201\n--- logs ---\n%s", resp.StatusCode, logs.String())
	}

	// 4b) Native WAF, hermetically: log in, create a WAF-enabled host, then prove the
	//     in-process Coraza engine (built into the real binary, no plugin/Docker) blocks
	//     an attack at the edge. A benign request reaches the proxy (502: no backend).
	jar, _ := cookiejar.New(nil)
	authed := &http.Client{Jar: jar, Timeout: 2 * time.Second}
	if code := postJSON(t, authed, adminBase+"/api/login", `{"email":"admin@boot.test","password":"password123"}`); code != http.StatusOK {
		t.Fatalf("login = %d, want 200", code)
	}
	hostBody := `{"kind":"proxy","enabled":true,"domains":["waf.boot.test"],` +
		`"upstreams":[{"scheme":"http","host":"127.0.0.1","port":59999}],"tls":"none","waf":true}`
	if code := postJSON(t, authed, adminBase+"/api/hosts", hostBody); code != http.StatusCreated {
		t.Fatalf("create waf host = %d, want 201", code)
	}
	edgeReq := func(path string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://"+edgeAddr+path, nil)
		req.Host = "waf.boot.test"
		req.Header.Set("X-xgress-Cache-Token", "boot-edge-token")
		r, err := client.Do(req)
		if err != nil {
			return -1
		}
		r.Body.Close()
		return r.StatusCode
	}
	// The host index + WAF build land via the reload triggered by the create; poll briefly.
	deadline := time.Now().Add(10 * time.Second)
	var attackCode int
	for time.Now().Before(deadline) {
		attackCode = edgeReq("/?q=union%20select%201%20from%20users")
		if attackCode == http.StatusForbidden {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if attackCode != http.StatusForbidden {
		t.Errorf("native WAF: attack through edge = %d, want 403\n--- logs ---\n%s", attackCode, logs.String())
	}
	if benign := edgeReq("/healthz"); benign == http.StatusForbidden {
		t.Errorf("native WAF: benign request blocked (got 403); should pass to the proxy")
	}

	// 5) Graceful shutdown: SIGTERM → run() returns nil → process exits 0.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal: %v", err)
	}
	select {
	case err := <-exited:
		if err != nil {
			t.Fatalf("process exited non-zero on SIGTERM: %v\n--- logs ---\n%s", err, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("process did not shut down within 20s of SIGTERM\n--- logs ---\n%s", logs.String())
	}

	// 6) Coverage was emitted (proves the instrumented run() executed end to end).
	if entries, _ := os.ReadDir(covDir); len(entries) == 0 {
		t.Errorf("no coverage files written to GOCOVERDIR (instrumented run did not record)")
	} else {
		t.Logf("run() coverage captured: %d covdata file(s) in %s", len(entries), covDir)
	}
}

// buildInstrumentedXgress compiles cmd/xgress with coverage instrumentation into a temp
// binary and returns its path.
func buildInstrumentedXgress(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "xgress-boot")
	cmd := exec.Command("go", "build", "-cover", "-o", bin, "github.com/suckharder/xgress/cmd/xgress")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build instrumented xgress: %v\n%s", err, out)
	}
	return bin
}

// repoRoot returns the module root (two levels up from this test file).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

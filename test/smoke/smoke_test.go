//go:build smoke

// Package smoke is xgress's Tier C end-to-end test: it brings up the REAL shipped
// image (xgress:test) with docker compose, exactly as a user would run it, and drives
// the full NPM loop through it — first-run setup, login, create a proxy host, prove
// traffic reaches the upstream, disable it, prove hot-reload removes the route — then
// verifies the hardening posture (non-root PID 1, read-only FS, no root process).
//
// It is **table-driven over the shipped deployment variants** (single/external ×
// sqlite/postgres × memory/redis): each runs the same loop against its own dedicated
// docker-compose.smoke.<variant>.yml under an isolated compose project. Single-container
// Redis variants additionally prove the server-side cache is served from Redis; external
// variants drive traffic through a separate Traefik container while xgress runs `managed=false`.
//
// This is the only tier that exercises the Dockerfile, the entrypoint's privilege
// drop, PID-1 supervision, and the real Postgres/Redis/external-Traefik wiring.
//
// Run: make smoke  (builds xgress:test, then `go test -tags smoke ./test/smoke/...`).
// A single variant: `go test -tags smoke -run TestSmoke/external-postgres ./test/smoke/...`.
package smoke

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	whoamiDomain  = "whoami.test"
	whoamiMarker  = "Hostname:" // present in any traefik/whoami response body
	adminPassword = "password123"
)

// variant is one shipped deployment to smoke-test.
type variant struct {
	name        string // subtest name + compose-project suffix
	composeFile string // dedicated compose file under test/smoke/
	external    bool   // proxy is published by the `traefik` service (xgress runs managed=false)
	cacheCheck  bool   // enable per-host cache and assert it is served from Redis
	tlsCheck    bool   // upload a cert + TLS host and assert the leaf is served on :443
}

// The cache check runs for every Redis variant — single and external. The edge is
// token-gated (X-xgress-Cache-Token), so the external composes bind it on the network
// (XGRESS_EDGE_LISTEN=:9100 + XGRESS_EDGE_ADVERTISE=http://xgress:9100) and a separate Traefik
// can route cache-enabled hosts through it safely.
// tlsCheck is enabled on one single-container variant (proves in-image @@KEY
// injection + the supervised Traefik serving the leaf) and one external variant
// (proves the token-gated provider ships the decrypted key over the network to a
// separate Traefik). The other six skip it to keep smoke runtime flat.
var variants = []variant{
	{name: "default", composeFile: "docker-compose.smoke.yml", tlsCheck: true},
	{name: "postgres", composeFile: "docker-compose.smoke.postgres.yml"},
	{name: "redis", composeFile: "docker-compose.smoke.redis.yml", cacheCheck: true},
	{name: "postgres-redis", composeFile: "docker-compose.smoke.postgres-redis.yml", cacheCheck: true},
	{name: "external", composeFile: "docker-compose.smoke.external.yml", external: true, tlsCheck: true},
	{name: "external-postgres", composeFile: "docker-compose.smoke.external-postgres.yml", external: true},
	{name: "external-redis", composeFile: "docker-compose.smoke.external-redis.yml", external: true, cacheCheck: true},
	{name: "external-postgres-redis", composeFile: "docker-compose.smoke.external-postgres-redis.yml", external: true, cacheCheck: true},
}

func TestSmoke(t *testing.T) {
	requireDocker(t)
	requireImage(t, "xgress:test")
	assertShippedComposeHardened(t) // anti-drift on the shipped files (once)

	for _, v := range variants {
		v := v
		t.Run(v.name, func(t *testing.T) { runVariant(t, v) })
	}
}

// runVariant brings up one deployment, runs the proxy loop + variant-specific
// assertions, and the hardening checks, then tears it down.
func runVariant(t *testing.T, v variant) {
	dc := dockerCompose("xgress-smoke-"+v.name, filepath.Join(smokeDir(), v.composeFile))

	// Clean slate: a leftover /data volume would make setup return 409.
	_, _ = runDocker(t, dc("down", "-v", "--remove-orphans")...)
	if out, err := runDocker(t, dc("up", "-d")...); err != nil {
		t.Fatalf("compose up: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			dumpLogs(t, dc)
		}
		_, _ = runDocker(t, dc("down", "-v", "--remove-orphans")...)
	})

	adminBase := "http://" + composePort(t, dc, "xgress", 8088)
	proxySvc := "xgress"
	if v.external {
		proxySvc = "traefik"
	}
	proxyAddr := composePort(t, dc, proxySvc, 80)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	runProxyLoop(t, client, adminBase, proxyAddr, v)

	if v.cacheCheck {
		assertRedisHasKeys(t, dc) // the cache HIT above must have landed in Redis, not memory
	}

	if v.tlsCheck {
		// Reuse the logged-in session: upload a self-signed cert + TLS host and prove
		// the exact leaf is served on :443 (end-to-end @@KEY injection through the image).
		httpsAddr := composePort(t, dc, proxySvc, 443)
		runTLSCheck(t, client, adminBase, httpsAddr, v)
	}

	// Hardening — always on the xgress container (non-root PID 1 + read-only root FS),
	// in both single and external topologies. The stock Traefik container (external)
	// is not our hardened image and is intentionally not asserted on.
	assertPID1NonRoot(t, dc)
	assertNoRootProcess(t, dc)
	assertFilesystemPosture(t, dc)
}

// runProxyLoop runs setup → login → create host → proxy reaches whoami → disable →
// hot-reload 404. For redis variants it enables the cache and proves a cache HIT.
func runProxyLoop(t *testing.T, client *http.Client, adminBase, proxyAddr string, v variant) {
	t.Helper()
	proxyTimeout := 30 * time.Second
	if v.external {
		proxyTimeout = 50 * time.Second // + external Traefik startup / first poll
	}

	waitHTTP(t, adminBase+"/api/setup", 90*time.Second)
	if code, b := postJSON(t, client, adminBase+"/api/setup",
		`{"email":"admin@smoke.test","name":"Admin","password":"`+adminPassword+`"}`); code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", code, b)
	}
	if code, b := postJSON(t, client, adminBase+"/api/login",
		`{"email":"admin@smoke.test","password":"`+adminPassword+`"}`); code != http.StatusOK {
		t.Fatalf("login = %d: %s", code, b)
	}

	cacheField := ""
	if v.cacheCheck {
		// Enable the native server-side cache globally (backed by Redis via XGRESS_REDIS_URL).
		if code := putJSON(t, client, adminBase+"/api/plugins", `{"wafEnabled":false,"cacheEnabled":true}`); code != http.StatusOK {
			t.Fatalf("enable cache = %d", code)
		}
		cacheField = `,"cache":true`
	}

	hostBody := `{"kind":"proxy","enabled":true,"domains":["` + whoamiDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"none"` + cacheField + `}`
	code, b := postJSON(t, client, adminBase+"/api/hosts", hostBody)
	if code != http.StatusCreated {
		t.Fatalf("create host = %d: %s", code, b)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &created); err != nil || created.ID == "" {
		t.Fatalf("host id not returned: %v (%s)", err, b)
	}

	// Proxy reaches whoami (poll: Traefik hot-reloads ~1s; external also starts up).
	eventually(t, proxyTimeout, func() error {
		status, body, _, err := getThroughProxy(proxyAddr, whoamiDomain)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status %d", status)
		}
		if !strings.Contains(body, whoamiMarker) {
			return fmt.Errorf("body missing whoami marker: %.80q", body)
		}
		return nil
	})

	if v.cacheCheck {
		// A repeat GET must be served from the cache (the edge sets X-xgress-Cache).
		eventually(t, 15*time.Second, func() error {
			status, body, hdr, err := getThroughProxy(proxyAddr, whoamiDomain)
			if err != nil {
				return err
			}
			if status != http.StatusOK || !strings.Contains(body, whoamiMarker) {
				return fmt.Errorf("status %d", status)
			}
			if got := hdr.Get("X-xgress-Cache"); got != "HIT" {
				return fmt.Errorf("X-xgress-Cache = %q, want HIT", got)
			}
			return nil
		})
	}

	// Disabling the host hot-reloads to a 404 (route removed).
	disableBody := `{"kind":"proxy","enabled":false,"domains":["` + whoamiDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"none"}`
	if code := putJSON(t, client, adminBase+"/api/hosts/"+created.ID, disableBody); code != http.StatusOK {
		t.Fatalf("disable host = %d", code)
	}
	eventually(t, proxyTimeout, func() error {
		status, _, _, err := getThroughProxy(proxyAddr, whoamiDomain)
		if err != nil {
			return err
		}
		if status != http.StatusNotFound {
			return fmt.Errorf("status %d, want 404 after disable", status)
		}
		return nil
	})
}

// --- compose / docker plumbing ---------------------------------------------

func smokeDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Dir(f)
}

// dockerCompose returns a closure building `docker compose -p <project> -f <file> …`.
func dockerCompose(project, file string) func(...string) []string {
	return func(extra ...string) []string {
		return append([]string{"compose", "-p", project, "-f", file}, extra...)
	}
}

func runDocker(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	return string(out), err
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		t.Skipf("docker not available, skipping smoke tier: %v", err)
	}
}

func requireImage(t *testing.T, ref string) {
	t.Helper()
	if err := exec.Command("docker", "image", "inspect", ref).Run(); err != nil {
		t.Skipf("image %q not found — build it first (`make smoke`, or `docker build -t %s .`)", ref, ref)
	}
}

// composePort returns the loopback host address (host:port) the given container port
// is published on (ephemeral mapping discovered at runtime).
func composePort(t *testing.T, dc func(...string) []string, service string, port int) string {
	t.Helper()
	out, err := runDocker(t, dc("port", service, fmt.Sprint(port))...)
	if err != nil {
		t.Fatalf("compose port %s/%d: %v\n%s", service, port, err, out)
	}
	addr := strings.TrimSpace(out)
	if addr == "" || !strings.Contains(addr, ":") {
		t.Fatalf("no published mapping for %s/%d (got %q)", service, port, out)
	}
	// `docker compose port` can return one line per family; take the first.
	return strings.SplitN(addr, "\n", 2)[0]
}

func dumpLogs(t *testing.T, dc func(...string) []string) {
	t.Helper()
	out, _ := runDocker(t, dc("logs", "--no-color", "--tail", "150")...)
	t.Logf("--- compose logs ---\n%s", out)
}

// --- HTTP helpers -----------------------------------------------------------

func waitHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("admin API not ready at %s within %s: %v", url, timeout, last)
}

func postJSON(t *testing.T, client *http.Client, url, body string) (int, []byte) {
	t.Helper()
	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func putJSON(t *testing.T, client *http.Client, url, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// getThroughProxy issues a request to the proxy presenting hostHeader as Host, so
// Traefik routes by its Host(...) rule. Returns status, body, and response headers.
func getThroughProxy(proxyAddr, hostHeader string) (int, string, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/", nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Host = hostHeader
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header, nil
}

func eventually(t *testing.T, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if last = fn(); last == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %v", timeout, last)
}

// --- assertions -------------------------------------------------------------

// assertRedisHasKeys proves the server-side cache is actually backed by Redis (not
// the in-memory fallback): after a cache HIT, the Redis keyspace must be non-empty.
func assertRedisHasKeys(t *testing.T, dc func(...string) []string) {
	t.Helper()
	out, err := runDocker(t, dc("exec", "-T", "redis", "redis-cli", "DBSIZE")...)
	if err != nil {
		t.Fatalf("redis DBSIZE: %v\n%s", err, out)
	}
	fields := strings.Fields(strings.TrimSpace(out)) // "5" or "(integer) 5"
	n, perr := strconv.Atoi(fields[len(fields)-1])
	if perr != nil {
		t.Fatalf("parse DBSIZE %q: %v", out, perr)
	}
	if n <= 0 {
		t.Errorf("redis DBSIZE = %d, want > 0 (cache not served from Redis?)", n)
	}
}

// assertPID1NonRoot checks the supervised xgress process (PID 1) runs as a non-root
// user. NOTE: `docker exec id -u` would report root (the image sets no USER, so the
// exec session is root) — the privilege drop happens via setpriv on PID 1, so we
// must read PID 1's own uid from /proc.
func assertPID1NonRoot(t *testing.T, dc func(...string) []string) {
	t.Helper()
	out, err := runDocker(t, dc("exec", "-T", "xgress", "cat", "/proc/1/status")...)
	if err != nil {
		t.Fatalf("read /proc/1/status: %v\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line) // Uid: <real> <eff> <saved> <fs>
			if len(f) < 2 {
				t.Fatalf("malformed Uid line: %q", line)
			}
			if f[1] == "0" {
				t.Errorf("PID 1 runs as root (uid 0) — privilege drop regressed")
			}
			return
		}
	}
	t.Fatalf("no Uid line in /proc/1/status:\n%s", out)
}

// assertNoRootProcess verifies no process in the xgress container runs as root.
func assertNoRootProcess(t *testing.T, dc func(...string) []string) {
	t.Helper()
	cidOut, err := runDocker(t, dc("ps", "-q", "xgress")...)
	if err != nil || strings.TrimSpace(cidOut) == "" {
		t.Fatalf("resolve xgress container id: %v\n%s", err, cidOut)
	}
	cid := strings.SplitN(strings.TrimSpace(cidOut), "\n", 2)[0]
	top, err := runDocker(t, "top", cid)
	if err != nil {
		t.Fatalf("docker top: %v\n%s", err, top)
	}
	lines := strings.Split(strings.TrimSpace(top), "\n")
	if len(lines) < 2 {
		t.Fatalf("unexpected docker top output:\n%s", top)
	}
	for _, line := range lines[1:] { // skip the UID/PID/... header
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if uid := fields[0]; uid == "0" || uid == "root" {
			t.Errorf("a container process runs as root: %q", line)
		}
	}
}

// assertFilesystemPosture verifies the root FS is read-only while /data and /tmp are
// writable. The probes are user-precise because CAP_DAC_OVERRIDE is dropped:
//   - root owns / (mode 0755), so a root touch there fails ONLY if the mount is RO.
//   - /data is owned by the xgress user, so we probe it AS xgress (the runtime user).
//   - /tmp is tmpfs (mode 1777), writable by anyone.
func assertFilesystemPosture(t *testing.T, dc func(...string) []string) {
	t.Helper()
	touchAs := func(user, path string) error {
		args := []string{"exec", "-T"}
		if user != "" {
			args = append(args, "-u", user)
		}
		args = append(args, "xgress", "touch", path)
		return runErr(runDocker(t, dc(args...)...))
	}
	if touchAs("", "/smoke-probe-ro") == nil {
		t.Error("root filesystem is writable — read_only hardening regressed")
	}
	if err := touchAs("xgress", "/data/smoke-probe"); err != nil {
		t.Errorf("/data should be writable by the xgress user: %v", err)
	}
	if err := touchAs("", "/tmp/smoke-probe"); err != nil {
		t.Errorf("/tmp (tmpfs) should be writable: %v", err)
	}
}

// assertShippedComposeHardened guards against drift between these smoke files and the
// shipped compose files: the prod default keeps its hardening, and each variant
// carries its defining env.
func assertShippedComposeHardened(t *testing.T) {
	t.Helper()
	root := filepath.Join(smokeDir(), "..", "..")
	checks := map[string][]string{
		"docker-compose.yml":          {"read_only: true", "no-new-privileges:true", "cap_drop", "NET_BIND_SERVICE"},
		"docker-compose.postgres.yml": {"XGRESS_DB_DRIVER"},
		"docker-compose.redis.yml":    {"XGRESS_REDIS_URL"},
		"docker-compose.external.yml": {`XGRESS_TRAEFIK_MANAGED: "false"`},
	}
	for file, wants := range checks {
		data, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		s := string(data)
		for _, w := range wants {
			if !strings.Contains(s, w) {
				t.Errorf("%s lost expected directive %q (drift from smoke compose)", file, w)
			}
		}
	}
}

// runErr collapses (output, err) from runDocker into just the error.
func runErr(_ string, err error) error { return err }

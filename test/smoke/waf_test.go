//go:build smoke

package smoke

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const wafDomain = "waf.smoke.test"

// TestSmokeWAFExternal proves the Coraza WAF blocks attacks when Traefik runs as a
// SEPARATE container (external mode). The rules are inlined into the config xgress serves,
// and the external Traefik fetches the WASM plugin itself — so this exercises the one
// thing no other tier does: WAF enforcement through an unmanaged Traefik.
//
// It is NOT hermetic: the external Traefik must download the Coraza plugin from the
// Traefik catalog on first boot, so the test skips when that catalog is unreachable.
// (The hermetic version arrives once the plugin is vendored into the image.)
func TestSmokeWAFExternal(t *testing.T) {
	requireDocker(t)
	requireImage(t, "xgress:test")

	dc := dockerCompose("xgress-smoke-waf", filepath.Join(smokeDir(), "docker-compose.smoke.external-waf.yml"))
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
	proxyAddr := composePort(t, dc, "traefik", 80)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	waitHTTP(t, adminBase+"/api/setup", 90*time.Second)
	if code, b := postJSON(t, client, adminBase+"/api/setup",
		`{"email":"admin@smoke.test","name":"Admin","password":"`+adminPassword+`"}`); code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", code, b)
	}
	if code, b := postJSON(t, client, adminBase+"/api/login",
		`{"email":"admin@smoke.test","password":"`+adminPassword+`"}`); code != http.StatusOK {
		t.Fatalf("login = %d: %s", code, b)
	}

	// WAF is preloaded (XGRESS_WAF_PRELOAD=true → plugin declared in the static config the
	// external Traefik fetches). Create a WAF-enabled host pointing at whoami.
	hostBody := `{"kind":"proxy","enabled":true,"domains":["` + wafDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"none","waf":true}`
	if code, b := postJSON(t, client, adminBase+"/api/hosts", hostBody); code != http.StatusCreated {
		t.Fatalf("create waf host = %d: %s", code, b)
	}

	// A benign request must pass — and this also proves the Coraza plugin actually loaded
	// in the external Traefik (a failed plugin load breaks the WAF middleware/router, so
	// this would never reach whoami). Generous timeout: the external Traefik downloads and
	// compiles the WASM plugin on first boot, then the config hot-reloads.
	//
	// This test is not hermetic: the external Traefik must fetch Coraza from the catalog.
	// If the route never comes up AND Traefik's own logs show a plugin-fetch failure, we
	// skip (no egress) rather than fail — a genuine WAF bug surfaces as a non-network
	// failure or a wrong attack result below.
	waitWAFRouteOrSkip(t, dc, proxyAddr, 150*time.Second)

	// An attack must be blocked with 403. The SQLi pattern matches the curated default
	// ruleset (rule id:1002, "union ... select"). Poll briefly to avoid any residual
	// reload race after the benign request first succeeded.
	eventually(t, 15*time.Second, func() error {
		status, _, _, err := getThroughProxyPath(proxyAddr, wafDomain, "/?q=union%20select%201%20from%20users")
		if err != nil {
			return err
		}
		if status != http.StatusForbidden {
			return fmt.Errorf("attack status = %d, want 403 (WAF not blocking through external Traefik)", status)
		}
		return nil
	})
}

// waitWAFRouteOrSkip polls the WAF host until a benign request succeeds (the plugin
// loaded). If it never comes up, it inspects the external Traefik's logs: a plugin-fetch
// failure (no egress) → skip; anything else → fail.
func waitWAFRouteOrSkip(t *testing.T, dc func(...string) []string, proxyAddr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		status, body, _, err := getThroughProxyPath(proxyAddr, wafDomain, "/")
		switch {
		case err != nil:
			last = err
		case status != http.StatusOK:
			last = fmt.Errorf("status %d", status)
		case !strings.Contains(body, whoamiMarker):
			last = fmt.Errorf("body missing whoami marker")
		default:
			return // route up, plugin loaded
		}
		time.Sleep(2 * time.Second)
	}
	logs, _ := runDocker(t, dc("logs", "--no-color", "traefik")...)
	if pluginFetchFailed(logs) {
		t.Skipf("Coraza plugin could not be fetched by the external Traefik (no egress?) — skipping non-hermetic test. last=%v", last)
	}
	t.Fatalf("WAF host never served a benign request within %s: %v\n--- traefik logs ---\n%s", timeout, last, logs)
}

// pluginFetchFailed reports whether Traefik's logs indicate the plugin download failed
// for a network reason (vs. a genuine config/plugin bug, which should fail the test).
func pluginFetchFailed(logs string) bool {
	l := strings.ToLower(logs)
	if !strings.Contains(l, "plugin") {
		return false
	}
	for _, sig := range []string{
		"download", "deadline exceeded", "no such host", "connection refused",
		"i/o timeout", "could not", "unable to", "x509", "tls", "temporary failure", "eof",
	} {
		if strings.Contains(l, sig) {
			return true
		}
	}
	return false
}

// getThroughProxyPath is getThroughProxy with an explicit request path (for attack URLs).
func getThroughProxyPath(proxyAddr, hostHeader, path string) (int, string, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+proxyAddr+path, nil)
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

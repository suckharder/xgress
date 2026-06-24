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

// TestSmokeWAFExternal proves the native Coraza WAF blocks attacks when Traefik
// runs as a SEPARATE container (external mode). The WAF runs in-process inside
// xgress: the external Traefik simply routes the WAF-enabled host to the
// token-gated xgress edge (http://xgress:9100), which inspects the request and
// returns 403 on an attack. No Traefik plugin, no catalog fetch — fully hermetic.
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

	// Create a WAF-enabled host pointing at whoami. The WAF (native Coraza + OWASP
	// CRS) is always in the binary; no preload/catalog step.
	hostBody := `{"kind":"proxy","enabled":true,"domains":["` + wafDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"none","waf":true}`
	if code, b := postJSON(t, client, adminBase+"/api/hosts", hostBody); code != http.StatusCreated {
		t.Fatalf("create waf host = %d: %s", code, b)
	}

	// A benign request must pass (proves the route is up and the edge proxies through).
	eventually(t, 60*time.Second, func() error {
		status, body, _, err := getThroughProxyPath(proxyAddr, wafDomain, "/")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("benign status = %d, want 200", status)
		}
		if !strings.Contains(body, whoamiMarker) {
			return fmt.Errorf("benign body missing whoami marker")
		}
		return nil
	})

	// An attack must be blocked with 403 by the in-process WAF (SQLi pattern is a
	// headline OWASP CRS rule).
	eventually(t, 15*time.Second, func() error {
		status, _, _, err := getThroughProxyPath(proxyAddr, wafDomain, "/?q=union%20select%201%20from%20users")
		if err != nil {
			return err
		}
		if status != http.StatusForbidden {
			return fmt.Errorf("attack status = %d, want 403 (native WAF not blocking)", status)
		}
		return nil
	})
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

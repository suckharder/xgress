//go:build smoke

package smoke

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	acmeDomain = "acme.smoke.test"
	// pebbleImage matches the digest-pinned Pebble used by Tier B (test/e2e/pebble.go).
	pebbleImage = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
)

// TestSmokeACME proves ACME issuance end-to-end through the REAL image: the container
// orders a cert from a Pebble CA on the compose network (trusting Pebble's minica),
// issueAsync stores the encrypted key, and the managed Traefik serves the issued leaf
// on :443. This is the one path neither the uploaded-cert TLS smoke (in-image @@KEY
// serving) nor Tier B (in-process issuance) covers: in-container issuance + serving.
func TestSmokeACME(t *testing.T) {
	requireDocker(t)
	requireImage(t, "xgress:test")

	// lego (inside the container) must trust Pebble's ACME-API cert, which is signed
	// by the static minica baked into the Pebble image. Extract it for the bind mount.
	caPath := extractPebbleMinica(t)
	t.Cleanup(func() { _ = os.Remove(caPath) })

	dc := dockerCompose("xgress-smoke-acme", filepath.Join(smokeDir(), "docker-compose.smoke.acme.yml"))
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
	httpsAddr := composePort(t, dc, "xgress", 443)
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

	// Order an ACME cert through the image (POST → issueAsync → Obtain against Pebble).
	createCert, _ := json.Marshal(map[string]any{
		"type": "acme", "domains": []string{acmeDomain}, "challengeType": "http-01",
	})
	code, b := postJSON(t, client, adminBase+"/api/certificates", string(createCert))
	if code != http.StatusCreated {
		t.Fatalf("create acme cert = %d: %s", code, b)
	}
	var cert struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &cert); err != nil || cert.ID == "" {
		t.Fatalf("cert id not returned: %v (%s)", err, b)
	}

	// Issuance is async; poll the cert list until the container records it valid.
	// (There is no GET /api/certificates/{id}; the list is the read path.)
	eventually(t, 60*time.Second, func() error {
		_, body := getJSON(t, client, adminBase+"/api/certificates")
		var certs []struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			LastError string `json:"lastError"`
		}
		if err := json.Unmarshal(body, &certs); err != nil {
			return fmt.Errorf("list certs: %v (%s)", err, body)
		}
		for _, c := range certs {
			if c.ID == cert.ID {
				if c.Status == "valid" {
					return nil
				}
				return fmt.Errorf("status=%q lastError=%q", c.Status, c.LastError)
			}
		}
		return fmt.Errorf("cert %s not in list", cert.ID)
	})

	// A TLS host using the ACME cert; Traefik must serve the Pebble-issued leaf on :443.
	hostBody := `{"kind":"proxy","enabled":true,"domains":["` + acmeDomain +
		`"],"upstreams":[{"scheme":"http","host":"whoami","port":80}],"tls":"acme"}`
	if code, b := postJSON(t, client, adminBase+"/api/hosts", hostBody); code != http.StatusCreated {
		t.Fatalf("create acme host = %d: %s", code, b)
	}
	eventually(t, 30*time.Second, func() error {
		return dialAndCheckACMELeaf(httpsAddr, acmeDomain)
	})
}

// dialAndCheckACMELeaf asserts the leaf served for sni carries that SAN AND was issued
// by Pebble (not Traefik's default cert) — i.e. a real ACME leaf, served from the image.
func dialAndCheckACMELeaf(addr, sni string) error {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // we assert the SAN + issuer ourselves
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()
	peer := conn.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return fmt.Errorf("no peer certificate presented")
	}
	leaf := peer[0]
	hasSAN := false
	for _, name := range leaf.DNSNames {
		if name == sni {
			hasSAN = true
		}
	}
	if !hasSAN {
		return fmt.Errorf("served cert SAN %v does not include %q (default cert?)", leaf.DNSNames, sni)
	}
	if !strings.Contains(leaf.Issuer.CommonName, "Pebble") {
		return fmt.Errorf("served leaf issuer = %q, want a Pebble-issued cert (Traefik default still in use?)", leaf.Issuer.CommonName)
	}
	return nil
}

// extractPebbleMinica copies Pebble's static minica out of the image to ./testdata so
// the compose can bind-mount it into the container as the lego trust root.
func extractPebbleMinica(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(smokeDir(), "testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	path := filepath.Join(dir, "pebble.minica.pem")

	out, err := exec.Command("docker", "create", pebbleImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker create pebble: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	defer func() { _ = exec.Command("docker", "rm", id).Run() }()

	if out, err := exec.Command("docker", "cp", id+":/test/certs/pebble.minica.pem", path).CombinedOutput(); err != nil {
		t.Fatalf("docker cp minica: %v\n%s", err, out)
	}
	return path
}

// getJSON issues a GET and returns status + body (companion to postJSON/putJSON).
func getJSON(t *testing.T, client *http.Client, url string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

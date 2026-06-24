//go:build integration

package e2e

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// pebbleImage is the digest-pinned Pebble test CA (matches the Dockerfile's
// digest-pinning posture so the test CA can't be silently swapped).
const pebbleImage = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"

// challTestSrvImage is the digest-pinned pebble-challtestsrv (mock DNS + HTTP
// challenge server with a programmable management API). Used by the DNS-01 tier.
const challTestSrvImage = "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b"

// pebbleHTTP01Port is the port Pebble's validation authority connects to for
// HTTP-01 (test/config/pebble-config.json: "httpPort": 5002). The real-callback
// test (B2) serves the challenge responder here.
const pebbleHTTP01Port = 5002

// pebble is a running Pebble test CA.
type pebble struct {
	dirURL string // ACME directory, e.g. https://127.0.0.1:<port>/dir
	caPEM  string // path to the minica that signs Pebble's ACME API cert (for LEGO_CA_CERTIFICATES)
}

// pebbleOpts configures a Pebble container.
type pebbleOpts struct {
	alwaysValid bool     // PEBBLE_VA_ALWAYS_VALID (skip real validation — B1)
	runArgs     []string // extra `docker run` args before the image (e.g. --add-host, --network)
	cmdArgs     []string // pebble command args after the image (e.g. -dnsserver)
}

// startPebble runs a Pebble test CA. alwaysValid makes the VA mark every challenge
// valid without connecting back (B1); false performs real validation (B2/DNS-01).
// extraArgs are appended to `docker run` (e.g. --add-host). Skips without Docker.
func startPebble(t *testing.T, alwaysValid bool, extraArgs ...string) pebble {
	return startPebbleOpts(t, pebbleOpts{alwaysValid: alwaysValid, runArgs: extraArgs})
}

// startPebbleOpts is the full-control variant (network membership, command flags).
func startPebbleOpts(t *testing.T, o pebbleOpts) pebble {
	t.Helper()
	requireDocker(t)

	// Ephemeral host ports (-p with only the container port) avoid collisions; the
	// actual mappings are discovered via `docker port` below.
	args := []string{
		"run", "-d", "--rm",
		"-p", "14000", "-p", "15000",
		"-e", "PEBBLE_VA_NOSLEEP=1", // no random pre-validation sleep
		"-e", "PEBBLE_WFE_NONCEREJECT=0", // deterministic: don't reject good nonces
	}
	if o.alwaysValid {
		args = append(args, "-e", "PEBBLE_VA_ALWAYS_VALID=1")
	}
	args = append(args, o.runArgs...)
	args = append(args, pebbleImage)
	args = append(args, o.cmdArgs...)

	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run pebble: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	dirPort := dockerHostPort(t, id, 14000)
	dirURL := fmt.Sprintf("https://127.0.0.1:%d/dir", dirPort)

	// Pebble's ACME API TLS cert is signed by a static minica baked into the image
	// (NOT the runtime issuance root at /roots/0). The bootstrap readiness client
	// skips verification; lego then verifies properly via the minica captured below.
	insecure := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // bootstrap readiness only
	}
	if err := waitReadyWith(insecure, dirURL, 25*time.Second); err != nil {
		dumpDockerLogs(t, id)
		t.Fatalf("pebble ACME directory not ready: %v", err)
	}

	caPEM := extractPebbleCA(t, id)
	return pebble{dirURL: dirURL, caPEM: caPEM}
}

// challSrv is a running pebble-challtestsrv (mock DNS + programmable mgmt API).
type challSrv struct {
	name        string // container name, for Pebble's -dnsserver <name>:8053 (in-network)
	mgmtURL     string // host URL of the management API (set-txt / clear-txt)
	dnsHostPort string // host TCP host:port of the DNS server (for lego's pre-check)
}

// startChallTestSrv runs pebble-challtestsrv on the given docker network. Only the
// TCP DNS port is published to the host: Docker Desktop (macOS) doesn't map ephemeral
// UDP ports, and lego's pre-check can run TCP-only (LEGO_EXPERIMENTAL_DNS_TCP_ONLY).
// Pebble itself reaches challtestsrv over the docker network (UDP+TCP), so its DNS
// resolution is unaffected.
func startChallTestSrv(t *testing.T, network string) challSrv {
	t.Helper()
	requireDocker(t)
	name := "xgress-cts-" + randSuffix()
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"--network", network, "--name", name,
		"-p", "8055", "-p", "8053/tcp",
		challTestSrvImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run challtestsrv: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })

	mgmtURL := fmt.Sprintf("http://127.0.0.1:%d", dockerHostPortProto(t, id, 8055, "tcp"))
	dnsHostPort := fmt.Sprintf("127.0.0.1:%d", dockerHostPortProto(t, id, 8053, "tcp"))

	// Readiness: the mgmt API has only POST routes, so any HTTP response (even 404)
	// means the server is up.
	if err := waitReachable(&http.Client{Timeout: time.Second}, mgmtURL+"/", 15*time.Second); err != nil {
		dumpDockerLogs(t, id)
		t.Fatalf("challtestsrv mgmt API not ready: %v", err)
	}
	return challSrv{name: name, mgmtURL: mgmtURL, dnsHostPort: dnsHostPort}
}

// dockerNetwork creates a user-defined bridge network (for container name
// resolution) and removes it on cleanup.
func dockerNetwork(t *testing.T) string {
	t.Helper()
	requireDocker(t)
	name := "xgress-net-" + randSuffix()
	if out, err := exec.Command("docker", "network", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })
	return name
}

func randSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// requireDocker skips the test unless a working Docker daemon is reachable.
func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Run(); err != nil {
		t.Skipf("docker not available, skipping container-based tier: %v", err)
	}
}

// dockerHostPort returns the host TCP port mapped to the container's containerPort.
func dockerHostPort(t *testing.T, id string, containerPort int) int {
	return dockerHostPortProto(t, id, containerPort, "tcp")
}

// dockerHostPortProto returns the host port mapped to containerPort/proto.
func dockerHostPortProto(t *testing.T, id string, containerPort int, proto string) int {
	t.Helper()
	out, err := exec.Command("docker", "port", id, fmt.Sprintf("%d/%s", containerPort, proto)).CombinedOutput()
	if err != nil {
		t.Fatalf("docker port %d/%s: %v\n%s", containerPort, proto, err, out)
	}
	// Output is one mapping per line, e.g. "0.0.0.0:51695\n[::]:51695".
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	i := strings.LastIndex(first, ":")
	if i < 0 {
		t.Fatalf("unexpected `docker port` output: %q", string(out))
	}
	p, err := strconv.Atoi(strings.TrimSpace(first[i+1:]))
	if err != nil {
		t.Fatalf("parse host port from %q: %v", first, err)
	}
	return p
}

// extractPebbleCA copies Pebble's static minica root — which signs its ACME API
// TLS certificate — out of the container, so lego can verify the directory
// endpoint. Returned as a path suitable for LEGO_CA_CERTIFICATES.
func extractPebbleCA(t *testing.T, id string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pebble.minica.pem")
	out, err := exec.Command("docker", "cp", id+":/test/certs/pebble.minica.pem", path).CombinedOutput()
	if err != nil {
		t.Fatalf("docker cp pebble minica: %v\n%s", err, out)
	}
	return path
}

func dumpDockerLogs(t *testing.T, id string) {
	t.Helper()
	out, _ := exec.Command("docker", "logs", id).CombinedOutput()
	t.Logf("--- pebble logs ---\n%s", out)
}

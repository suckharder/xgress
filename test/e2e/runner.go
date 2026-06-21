//go:build integration

package e2e

import (
	"os"
	"testing"

	"github.com/suckharder/xgress/internal/traefikcfg"
)

// traefikEnv abstracts where the real Traefik process runs and how it reaches the
// test's in-process servers (provider + upstream). It is the single seam that
// differs by platform: a native binary on macOS (today), a container on Linux
// (later). The contract assertions are written against this interface and never
// against any platform specifics, so adding the container runner is a drop-in.
type traefikEnv interface {
	// reachable rewrites a loopback host the test binds (e.g. "127.0.0.1") into one
	// the Traefik process can dial. Identity for the native runner; for a container
	// runner it maps loopback → "host.docker.internal".
	reachable(host string) string

	// run launches Traefik with the given static config, waits until it is ready,
	// and returns the endpoints the test should hit plus a stop func. It fails the
	// test (with Traefik's captured logs) if Traefik does not come up.
	run(t *testing.T, params traefikcfg.StaticParams) (traefikEndpoints, func())
}

// traefikEndpoints are the addresses the TEST hits to talk to the running Traefik.
type traefikEndpoints struct {
	web       string      // base URL of the HTTP entrypoint, e.g. http://127.0.0.1:18080
	websecure string      // host:port of the HTTPS entrypoint, for tls.Dial
	api       string      // base URL of Traefik's read-only API
	logs      *syncBuffer // Traefik's combined stdout+stderr, for log assertions
}

// newTraefikEnv selects the runner. Defaults by OS; XGRESS_E2E_TRAEFIK=native|docker
// forces a backend (useful for cross-checking the container path on macOS later).
func newTraefikEnv(t *testing.T) traefikEnv {
	switch os.Getenv("XGRESS_E2E_TRAEFIK") {
	case "native":
		return &nativeEnv{}
	case "docker":
		t.Skip("docker traefik runner not implemented yet (Linux tier) — set XGRESS_E2E_TRAEFIK=native or run on macOS")
		return nil
	}
	// Native is the only implemented backend today; the container runner will be
	// added when development moves to Linux.
	return &nativeEnv{}
}

//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
)

// TestACMEObtainDNS01Wildcard issues a real *wildcard* certificate via DNS-01
// against Pebble, with pebble-challtestsrv as the mock DNS server. It's the only
// automated proof that xgress's DNS-01 path (i.e. wildcard certs) works end to end:
// it exercises obtain()'s dns-01 branch, dnsProvider() (via lego's "exec" provider
// reading creds set by setEnv), and the DNSRecursiveNameservers pre-check override.
//
// Topology (all on one ephemeral docker network):
//   - challtestsrv: programmable DNS (TXT) + management API. Pebble resolves through
//     it (-dnsserver); lego's exec script publishes TXT records into it; lego's own
//     propagation pre-check queries it (via DNSRecursiveNameservers).
//   - pebble: real DNS-01 validation (NOT always-valid).
func TestACMEObtainDNS01Wildcard(t *testing.T) {
	requireDocker(t)
	const wildcard = "*.dns01.test"

	net := dockerNetwork(t)
	cts := startChallTestSrv(t, net)
	pe := startPebbleOpts(t, pebbleOpts{
		runArgs: []string{"--network", net},
		cmdArgs: []string{"-config", "/test/config/pebble-config.json", "-dnsserver", cts.name + ":8053"},
	})
	t.Setenv("LEGO_CA_CERTIFICATES", pe.caPEM)
	// Docker Desktop (macOS) doesn't publish ephemeral UDP ports, so lego's pre-check
	// queries challtestsrv over TCP. (Pebble's own resolution is UDP over the docker
	// network and is unaffected.)
	t.Setenv("LEGO_EXPERIMENTAL_DNS_TCP_ONLY", "1")

	mgr, st, box := newACMEManagerDNS(t, pe.dirURL, cts.dnsHostPort)
	ctx := context.Background()

	// lego "exec" DNS provider: our script publishes/clears TXT in challtestsrv.
	creds, _ := json.Marshal(map[string]string{
		"EXEC_PATH":                writeExecScript(t, cts.mgmtURL),
		"EXEC_PROPAGATION_TIMEOUT": "60",
		"EXEC_POLLING_INTERVAL":    "2",
	})
	enc, err := box.EncryptString(string(creds))
	if err != nil {
		t.Fatal(err)
	}
	dp := &store.DNSProvider{Name: "exec", Provider: "exec", ConfigEnc: enc}
	if err := st.CreateDNSProvider(ctx, dp); err != nil {
		t.Fatal(err)
	}

	cert := &store.Certificate{
		Type: store.CertTypeACME, Domains: []string{wildcard},
		ChallengeType: "dns-01", DNSProviderID: dp.ID, Status: store.CertStatusPending,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	if err := mgr.Obtain(ctx, cert); err != nil {
		t.Fatalf("Obtain (dns-01 wildcard): %v", err)
	}
	if cert.Status != store.CertStatusValid {
		t.Errorf("status = %q, want valid", cert.Status)
	}
	// The issued leaf must carry the wildcard SAN.
	assertLeafSAN(t, cert.CertPEM, wildcard)
	if _, err := box.DecryptString(cert.KeyPEMEnc); err != nil {
		t.Errorf("decrypt stored key: %v", err)
	}
	if cert.ExpiresAt == nil || !cert.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v, want a future time", cert.ExpiresAt)
	}
}

// newACMEManagerDNS builds an acme.Manager for the DNS-01 tier: pointed at Pebble
// (CADirURL) with the propagation pre-check aimed at challtestsrv (dnsResolver).
func newACMEManagerDNS(t *testing.T, dirURL, dnsResolver string) (*acme.Manager, *store.Store, *secrets.Box) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, &config.Config{DataDir: dir, DBDriver: config.DriverSQLite})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatalf("secrets.Load: %v", err)
	}
	mgr := acme.New(acme.Options{
		Store: st, Box: box, DefaultEmail: acmeEmail,
		CADirURL:                dirURL,
		DNSRecursiveNameservers: []string{dnsResolver},
		Logger:                  discardLogger(),
	})
	return mgr, st, box
}

// writeExecScript writes a lego "exec" DNS provider script that publishes/clears
// TXT records via the challtestsrv management API. lego (default mode) invokes it
// as `script <present|cleanup> <fqdn> <value>`.
func writeExecScript(t *testing.T, mgmtURL string) string {
	t.Helper()
	script := fmt.Sprintf(`#!/bin/sh
set -e
case "$1" in
  present) curl -fsS -X POST '%s/set-txt'   -d "{\"host\":\"$2\",\"value\":\"$3\"}" >/dev/null ;;
  cleanup) curl -fsS -X POST '%s/clear-txt' -d "{\"host\":\"$2\"}"                  >/dev/null ;;
esac
`, mgmtURL, mgmtURL)
	path := filepath.Join(t.TempDir(), "exec-dns.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write exec script: %v", err)
	}
	return path
}

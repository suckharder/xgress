//go:build integration

// Tier B — ACME issuance against a real (containerized) test CA, Pebble. This is
// the only automated coverage of the internal/acme package: it exercises the full
// acme.Manager.Obtain pipeline — account registration, order, HTTP-01 challenge,
// finalize, encrypted-key storage, and expiry parsing — against a CA that actually
// runs the ACME protocol.
//
//	B1 (TestACMEObtainAlwaysValid):       Pebble's VA marks challenges valid without
//	     connecting back. No host callback → bulletproof on any OS. Covers the whole
//	     issuance/storage/crypto path.
//	B2 (TestACMEObtainHTTP01RealValidation): Pebble performs REAL HTTP-01 validation,
//	     reaching the HTTP01Responder on the host via --add-host. Additionally proves
//	     the responder serves the challenge token to a real validation authority.
package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
)

const acmeEmail = "ops@e2e.test"

// newACMEManager builds an acme.Manager wired to a temp store + secrets box and
// pointed at the given ACME directory (Pebble) via the CADirURL override.
func newACMEManager(t *testing.T, dirURL string, responder *acme.HTTP01Responder) (*acme.Manager, *store.Store, *secrets.Box) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, DBDriver: config.DriverSQLite}
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatalf("secrets.Load: %v", err)
	}
	mgr := acme.New(acme.Options{
		Store: st, Box: box, Responder: responder,
		DefaultEmail: acmeEmail, CADirURL: dirURL, Logger: discardLogger(),
	})
	return mgr, st, box
}

// B1: full issuance pipeline, validation short-circuited by the CA.
func TestACMEObtainAlwaysValid(t *testing.T) {
	pe := startPebble(t, true)
	t.Setenv("LEGO_CA_CERTIFICATES", pe.caPEM) // make lego trust Pebble's runtime CA
	mgr, st, box := newACMEManager(t, pe.dirURL, acme.NewHTTP01Responder())
	ctx := context.Background()

	cert := &store.Certificate{
		Type: store.CertTypeACME, Domains: []string{"acme-e2e.test"},
		ChallengeType: "http-01", Status: store.CertStatusPending,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := mgr.Obtain(ctx, cert); err != nil {
		t.Fatalf("Obtain: %v", err)
	}

	// B1.1 — issuance succeeded and was recorded.
	if cert.Status != store.CertStatusValid {
		t.Errorf("status = %q, want valid", cert.Status)
	}
	if cert.LastError != "" {
		t.Errorf("lastError = %q, want empty", cert.LastError)
	}
	// B1.2 — a real leaf was issued for the requested domain.
	assertLeafSAN(t, cert.CertPEM, "acme-e2e.test")
	// B1.3 — the private key was stored encrypted and decrypts to a valid key.
	keyPEM, err := box.DecryptString(cert.KeyPEMEnc)
	if err != nil {
		t.Fatalf("decrypt stored key: %v", err)
	}
	assertValidKeyPEM(t, keyPEM)
	// B1.4 — expiry was parsed from the issued cert (leafExpiry).
	if cert.ExpiresAt == nil || !cert.ExpiresAt.After(time.Now()) {
		t.Errorf("ExpiresAt = %v, want a future time", cert.ExpiresAt)
	}

	// B1.5 — the ACME account was registered + persisted, and a second issuance
	// reuses it rather than re-registering (same encrypted account key).
	acct, err := st.GetACMEAccountByEmail(ctx, acmeEmail, pe.dirURL)
	if err != nil {
		t.Fatalf("ACME account not persisted: %v", err)
	}
	cert2 := &store.Certificate{
		Type: store.CertTypeACME, Domains: []string{"acme-e2e-second.test"},
		ChallengeType: "http-01", Status: store.CertStatusPending,
	}
	if err := st.CreateCertificate(ctx, cert2); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Obtain(ctx, cert2); err != nil {
		t.Fatalf("second Obtain: %v", err)
	}
	acct2, err := st.GetACMEAccountByEmail(ctx, acmeEmail, pe.dirURL)
	if err != nil {
		t.Fatalf("ACME account missing after second issuance: %v", err)
	}
	if acct2.PrivateKeyEnc != acct.PrivateKeyEnc {
		t.Error("second issuance re-registered the ACME account instead of reusing it")
	}
}

// B2: real HTTP-01 validation that traverses the responder.
func TestACMEObtainHTTP01RealValidation(t *testing.T) {
	requireDocker(t)
	const domain = "acme-e2e.test"

	// Serve the SAME responder instance the manager uses, on Pebble's HTTP-01 port,
	// so Pebble can fetch the challenge token from the host.
	responder := acme.NewHTTP01Responder()
	var served atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		responder.ServeHTTP(w, r)
	})
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", pebbleHTTP01Port))
	if err != nil {
		t.Skipf("cannot bind :%d for the HTTP-01 responder (in use?): %v", pebbleHTTP01Port, err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// Pebble resolves the cert domain to the host gateway, so its VA reaches the
	// responder above. Real validation (alwaysValid=false).
	pe := startPebble(t, false, "--add-host", domain+":host-gateway")
	t.Setenv("LEGO_CA_CERTIFICATES", pe.caPEM)
	mgr, st, box := newACMEManager(t, pe.dirURL, responder)
	ctx := context.Background()

	cert := &store.Certificate{
		Type: store.CertTypeACME, Domains: []string{domain},
		ChallengeType: "http-01", Status: store.CertStatusPending,
	}
	if err := st.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := mgr.Obtain(ctx, cert); err != nil {
		t.Fatalf("Obtain via real HTTP-01: %v", err)
	}

	if cert.Status != store.CertStatusValid {
		t.Errorf("status = %q, want valid", cert.Status)
	}
	assertLeafSAN(t, cert.CertPEM, domain)
	if _, err := box.DecryptString(cert.KeyPEMEnc); err != nil {
		t.Errorf("decrypt stored key: %v", err)
	}
	// B2.1 — real validation actually traversed the responder (the CA fetched the
	// challenge token over HTTP from ServeHTTP).
	if served.Load() == 0 {
		t.Error("HTTP01Responder was never hit — real HTTP-01 validation did not traverse it")
	}
}

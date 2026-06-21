//go:build integration

// HA tier: multi-node ACME leader election on a shared Postgres. The engine's
// renewal pass elects a single leader via store.AcquireLease so only one instance
// renews (avoiding duplicate ACME orders / rate limits). The unit suite proves the
// engine HONORS the lease (internal/engine/renewal_test.go); this proves the lease
// itself behaves correctly across TWO independent Postgres connections — mutual
// exclusion and failover when the holder dies — which sqlite-in-one-process can't
// represent.
package e2e

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/engine"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
)

// TestHALeaseFailoverPostgres is the HA failover scenario: two xgress instances on a
// shared Postgres; the lease holder "dies", and renewal leadership fails over to the
// other. It also exercises the Postgres-specific PK-conflict path: the second
// instance's UPDATE matches no row, so it INSERTs and must hit the leases primary-key
// violation → denied. (If leases.name lost its PRIMARY KEY, both nodes would "win"
// and this test would fail — i.e. it has teeth.)
func TestHALeaseFailoverPostgres(t *testing.T) {
	dsn := startPostgres(t)
	ctx := context.Background()

	// Two independent connection pools = two xgress instances sharing one database.
	nodeA := openPGStore(t, dsn)
	nodeB := openPGStore(t, dsn)

	const lease = "acme-renewal"
	// AcquireLease compares lease times at SECOND granularity (time.Now().Unix()), so
	// margins must clear whole-second truncation: a short TTL plus a sleep that exceeds
	// it by >1s guarantees the lease is unambiguously expired at takeover.
	ttl := 1 * time.Second

	// node-a takes the lease (first AcquireLease INSERTs the row).
	if ok, err := nodeA.AcquireLease(ctx, lease, "node-a", ttl); err != nil || !ok {
		t.Fatalf("node-a acquire: ok=%v err=%v", ok, err)
	}
	// node-b is denied while node-a holds it (cross-connection mutual exclusion via
	// the PK-conflict path).
	if ok, err := nodeB.AcquireLease(ctx, lease, "node-b", ttl); err != nil || ok {
		t.Fatalf("node-b must be denied while node-a holds: ok=%v err=%v", ok, err)
	}
	// node-a refreshes its own lease (the UPDATE matches on holder=node-a).
	if ok, err := nodeA.AcquireLease(ctx, lease, "node-a", ttl); err != nil || !ok {
		t.Fatalf("node-a refresh: ok=%v err=%v", ok, err)
	}

	// node-a "dies": stop refreshing and let the lease expire (well past the TTL to
	// clear second-granularity truncation).
	time.Sleep(ttl + 2*time.Second)

	// Failover: node-b takes over the now-expired lease (the UPDATE matches on
	// expires_at < now).
	if ok, err := nodeB.AcquireLease(ctx, lease, "node-b", time.Minute); err != nil || !ok {
		t.Fatalf("node-b takeover after expiry: ok=%v err=%v", ok, err)
	}
	// node-a (recovered) cannot reclaim the lease now held (unexpired) by node-b.
	if ok, err := nodeA.AcquireLease(ctx, lease, "node-a", ttl); err != nil || ok {
		t.Errorf("node-a reclaimed a lease held by node-b: ok=%v err=%v", ok, err)
	}
}

// TestHARenewalFailoverPostgres is the full end-to-end HA scenario: two engines share
// one Postgres, each with a real ACME manager pointed at a Pebble CA. A due cert is
// renewed by whichever engine wins leadership; we then kill the leader and force the
// cert due again, and assert the SURVIVOR takes over the (expired) lease and renews it.
// This proves the background renewal loop — not just the lease primitive — fails over.
// Uses XGRESS_RENEWAL_INTERVAL/_LEASE_TTL (short) so it runs in seconds.
func TestHARenewalFailoverPostgres(t *testing.T) {
	dsn := startPostgres(t)
	pe := startPebble(t, true) // always-valid VA: issuance succeeds without a callback
	t.Setenv("LEGO_CA_CERTIFICATES", pe.caPEM)
	ctx := context.Background()

	// Both instances MUST share the secrets key (as in real HA): the ACME account key
	// is encrypted at rest in the shared DB, so the survivor can only decrypt and reuse
	// the account the leader registered if it holds the same key.
	sharedKey := filepath.Join(t.TempDir(), "secret.key")
	eA, stA := newRenewalEngine(t, dsn, sharedKey, pe.dirURL, "node-a")
	eB, _ := newRenewalEngine(t, dsn, sharedKey, pe.dirURL, "node-b")

	// Seed a DUE ACME cert (already expired, auto-renew) in the shared database.
	past := time.Now().Add(-24 * time.Hour)
	cert := &store.Certificate{
		Type: store.CertTypeACME, Domains: []string{"ha-renew.test"},
		ChallengeType: "http-01", Status: store.CertStatusValid,
		ExpiresAt: &past, AutoRenew: true,
	}
	if err := stA.CreateCertificate(ctx, cert); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	certID := cert.ID

	// Start both renewal loops (1s interval, 3s lease TTL — set in newRenewalEngine).
	ctxA, cancelA := context.WithCancel(ctx)
	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelA()
	defer cancelB()
	eA.StartBackground(ctxA)
	eB.StartBackground(ctxB)

	// Phase 1 — the elected leader renews the due cert (expiry moves to the future).
	waitCertRenewed(t, stA, certID, 25*time.Second)
	leader := leaseHolder(t, dsn)
	if leader != "node-a" && leader != "node-b" {
		t.Fatalf("unexpected lease holder %q", leader)
	}

	// Kill the leader: cancel its loop (stops renewing AND refreshing the lease).
	if leader == "node-a" {
		cancelA()
	} else {
		cancelB()
	}

	// Force the cert due again so the survivor has work to do.
	c, err := stA.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	c.ExpiresAt = &past
	if err := stA.UpdateCertificate(ctx, c); err != nil {
		t.Fatalf("re-expire cert: %v", err)
	}

	// Phase 2 — the survivor takes over the expired lease and renews. Failover.
	waitCertRenewed(t, stA, certID, 30*time.Second)
	if got := leaseHolder(t, dsn); got == leader {
		t.Errorf("lease holder still %q after killing it — renewal did not fail over", leader)
	}
}

// newRenewalEngine builds an engine on the shared Postgres DSN with a real ACME
// manager pointed at caURL (Pebble) and a short renewal cadence, identified by holderID.
func newRenewalEngine(t *testing.T, dsn, keyFile, caURL, holderID string) (*engine.Engine, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: dir, DBDriver: config.DriverPostgres, DBDSN: dsn,
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure", HTTPPort: 80, HTTPSPort: 443,
		RenewalInterval: time.Second, RenewalLeaseTTL: 3 * time.Second,
	}
	st, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(keyFile) // shared across instances (real-HA requirement)
	if err != nil {
		t.Fatalf("secrets.Load: %v", err)
	}
	am := acme.New(acme.Options{
		Store: st, Box: box, Responder: acme.NewHTTP01Responder(),
		DefaultEmail: "ha@e2e.test", CADirURL: caURL, Logger: discardLogger(),
	})
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: discardLogger()})
	e := engine.New(cfg, st, box, sup, am, "", discardLogger())
	e.SetHolderID(holderID)
	return e, st
}

// waitCertRenewed polls until the cert's expiry is in the future (i.e. it was renewed).
func waitCertRenewed(t *testing.T, st *store.Store, id string, timeout time.Duration) {
	t.Helper()
	eventually(t, timeout, func() error {
		c, err := st.GetCertificate(context.Background(), id)
		if err != nil {
			return err
		}
		if c.ExpiresAt == nil || !c.ExpiresAt.After(time.Now()) {
			return errStatus(0) // not yet renewed
		}
		return nil
	})
}

// leaseHolder reads the current holder of the acme-renewal lease from Postgres.
func leaseHolder(t *testing.T, dsn string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	var holder string
	err = db.QueryRow("SELECT holder FROM leases WHERE name = 'acme-renewal'").Scan(&holder)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("query lease holder: %v", err)
	}
	return holder
}

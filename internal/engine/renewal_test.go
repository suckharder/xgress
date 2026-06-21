package engine

import (
	"context"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/store"
)

// TestRenewalSkippedWhenNotLeader proves the renewal pass honors the leader-election
// lease: when another instance holds "acme-renewal", renewDueCertificates must bail
// out at the lease guard BEFORE touching any certificate. The engine is built with a
// nil ACME manager and a DUE cert is seeded, so if the guard ever regressed the code
// would reach e.acme.Obtain and panic (nil deref) — i.e. this test has teeth.
func TestRenewalSkippedWhenNotLeader(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	seedDueACMECert(t, e, "skip.example.com")

	// Another instance already holds the renewal lease.
	ok, err := e.st.AcquireLease(ctx, "acme-renewal", "other-node", time.Minute)
	if err != nil || !ok {
		t.Fatalf("pre-acquire lease: ok=%v err=%v", ok, err)
	}

	// Must not panic and must not renew (acme is nil; reaching it would deref-panic).
	e.renewDueCertificates(ctx)

	// The lease is still held by the other node (we did not steal it).
	if ok, _ := e.st.AcquireLease(ctx, "acme-renewal", "third-node", time.Minute); ok {
		t.Error("non-leader renewal pass stole/expired the lease held by other-node")
	}
}

// TestRenewalAcquiresLeaseWhenLeader proves the opposite path: with the lease free and
// nothing due, the pass acquires the lease (becomes the leader) and does no ACME work.
func TestRenewalAcquiresLeaseWhenLeader(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// No due certs → the pass acquires the lease and returns without calling ACME.
	e.renewDueCertificates(ctx)

	// We now hold "acme-renewal"; another holder cannot take it.
	if ok, _ := e.st.AcquireLease(ctx, "acme-renewal", "other-node", time.Minute); ok {
		t.Error("renewal pass did not hold the lease after running as leader")
	}
}

// seedDueACMECert inserts an auto-renew ACME cert that is already past the 30-day
// renewal threshold, so a leader pass would attempt to renew it.
func seedDueACMECert(t *testing.T, e *Engine, domain string) {
	t.Helper()
	past := time.Now().Add(-24 * time.Hour)
	c := &store.Certificate{
		Type:      store.CertTypeACME,
		Domains:   []string{domain},
		Status:    store.CertStatusValid,
		ExpiresAt: &past,
		AutoRenew: true,
	}
	if err := e.st.CreateCertificate(context.Background(), c); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

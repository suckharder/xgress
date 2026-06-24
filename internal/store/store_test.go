package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/config"
)

// TestCreateFirstUserAtomic fires many concurrent first-run inserts with distinct
// emails and asserts exactly one wins — the check-then-act race in POST /api/setup
// can no longer create rival admin accounts.
func TestCreateFirstUserAtomic(t *testing.T) {
	st, ctx := newTestStore(t)
	const n = 20
	var wg sync.WaitGroup
	var created int32
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := &User{Email: fmt.Sprintf("admin%d@example.com", i), Name: "Admin", PasswordHash: "x", Role: RoleAdmin}
			ok, err := st.CreateFirstUser(ctx, u)
			errs[i] = err
			if ok {
				atomic.AddInt32(&created, 1)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("CreateFirstUser[%d] errored: %v", i, err)
		}
	}
	if created != 1 {
		t.Fatalf("exactly one first user must be created, got %d", created)
	}
	if cnt, _ := st.CountUsers(ctx); cnt != 1 {
		t.Fatalf("user count = %d, want 1", cnt)
	}
}

// newTestStore opens a throwaway SQLite store in a temp dir with all migrations
// applied. Each test gets an isolated database.
func newTestStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir(), DBDriver: config.DriverSQLite}
	ctx := context.Background()
	st, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, ctx
}

func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, DBDriver: config.DriverSQLite}
	ctx := context.Background()

	st, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Every migration recorded.
	var n int
	if err := st.queryRow(ctx, `SELECT COUNT(1) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n < 4 {
		t.Fatalf("expected >=4 migrations applied, got %d", n)
	}
	// Core tables exist and are queryable.
	for _, tbl := range []string{"users", "hosts", "middlewares", "certificates", "access_lists", "bans", "settings", "config_snapshots", "sessions", "schedules", "leases"} {
		if _, err := st.exec(ctx, `SELECT COUNT(1) FROM `+tbl); err != nil {
			t.Errorf("table %q not usable: %v", tbl, err)
		}
	}
	_ = st.Close()

	// Reopening must not re-run migrations or error (idempotent).
	st2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	var n2 int
	if err := st2.queryRow(ctx, `SELECT COUNT(1) FROM schema_migrations`).Scan(&n2); err != nil {
		t.Fatal(err)
	}
	if n2 != n {
		t.Fatalf("migration count changed on reopen: %d -> %d", n, n2)
	}
}

func TestRebind(t *testing.T) {
	sqlite := &Store{dialect: DialectSQLite}
	pg := &Store{dialect: DialectPostgres}
	q := `SELECT * FROM t WHERE a = ? AND b = ? OR c = ?`
	if got := sqlite.rebind(q); got != q {
		t.Errorf("sqlite rebind changed query: %q", got)
	}
	want := `SELECT * FROM t WHERE a = $1 AND b = $2 OR c = $3`
	if got := pg.rebind(q); got != want {
		t.Errorf("pg rebind = %q, want %q", got, want)
	}
}

func TestUserCRUDAndUniqueness(t *testing.T) {
	st, ctx := newTestStore(t)

	if c, _ := st.CountUsers(ctx); c != 0 {
		t.Fatalf("fresh store has %d users, want 0", c)
	}

	u := &User{Email: "admin@example.com", Name: "Admin", PasswordHash: "hash", Role: RoleAdmin}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" {
		t.Fatal("CreateUser did not assign an ID")
	}
	if u.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not set")
	}

	if c, _ := st.CountUsers(ctx); c != 1 {
		t.Fatalf("CountUsers = %d, want 1", c)
	}

	got, err := st.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Email != "admin@example.com" || got.Role != RoleAdmin {
		t.Fatalf("GetUser mismatch: %+v", got)
	}

	byEmail, err := st.GetUserByEmail(ctx, "admin@example.com")
	if err != nil || byEmail.ID != u.ID {
		t.Fatalf("GetUserByEmail: %v / %+v", err, byEmail)
	}

	// Duplicate email must violate the unique constraint.
	dup := &User{Email: "admin@example.com", Name: "Dup", PasswordHash: "x", Role: RoleViewer}
	if err := st.CreateUser(ctx, dup); err == nil {
		t.Fatal("expected unique-constraint error on duplicate email")
	}

	// Update.
	got.Name = "Renamed"
	got.Role = RoleOperator
	if err := st.UpdateUser(ctx, got); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	reload, _ := st.GetUser(ctx, u.ID)
	if reload.Name != "Renamed" || reload.Role != RoleOperator {
		t.Fatalf("update not persisted: %+v", reload)
	}

	// Delete.
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := st.GetUser(ctx, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser after delete = %v, want ErrNotFound", err)
	}
}

func TestGetMissingReturnsNotFound(t *testing.T) {
	st, ctx := newTestStore(t)
	if _, err := st.GetUser(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetUser missing: %v", err)
	}
	if _, err := st.GetHost(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetHost missing: %v", err)
	}
	if _, err := st.GetCertificate(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCertificate missing: %v", err)
	}
	if _, err := st.GetMiddleware(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetMiddleware missing: %v", err)
	}
}

func TestHostRoundTripPreservesComplexFields(t *testing.T) {
	st, ctx := newTestStore(t)
	h := &Host{
		Kind:    HostKindProxy,
		Enabled: true,
		Domains: []string{"a.example.com", "b.example.com"},
		Upstreams: []Upstream{
			{Scheme: "http", Host: "10.0.0.1", Port: 8080, Weight: 3},
			{Scheme: "https", Host: "10.0.0.2", Port: 8443, Weight: 1},
		},
		LoadBalancer:  "wrr",
		Sticky:        true,
		TLS:           TLSACME,
		ForceTLS:      true,
		HSTS:          true,
		WAF:           true,
		MiddlewareIDs: []string{"mw1", "mw2"},
		AccessListIDs: []string{"acl1"},
		ServiceMode:   "weighted",
		BackendGroups: []BackendGroup{
			{Name: "blue", Upstreams: []Upstream{{Scheme: "http", Host: "b", Port: 80}}, Weight: 90},
			{Name: "green", Upstreams: []Upstream{{Scheme: "http", Host: "g", Port: 80}}, Weight: 10},
		},
		ErrorPages:           []ErrorPage{{Status: "404", HTML: "<h1>gone</h1>"}},
		CORSEnabled:          true,
		CORSAllowOrigins:     []string{"https://app.example.com", "https://admin.example.com"},
		CORSAllowCredentials: true,
		Notes:                "primary",
	}
	if err := st.CreateHost(ctx, h); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	got, err := st.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if len(got.Domains) != 2 || got.Domains[1] != "b.example.com" {
		t.Errorf("domains lost: %v", got.Domains)
	}
	if len(got.Upstreams) != 2 || got.Upstreams[0].Weight != 3 || got.Upstreams[1].Port != 8443 {
		t.Errorf("upstreams lost: %+v", got.Upstreams)
	}
	if got.LoadBalancer != "wrr" || !got.Sticky || got.TLS != TLSACME || !got.WAF {
		t.Errorf("scalar fields lost: %+v", got)
	}
	if len(got.MiddlewareIDs) != 2 || len(got.AccessListIDs) != 1 {
		t.Errorf("attachment ids lost: mw=%v acl=%v", got.MiddlewareIDs, got.AccessListIDs)
	}
	if got.ServiceMode != "weighted" || len(got.BackendGroups) != 2 || got.BackendGroups[0].Weight != 90 {
		t.Errorf("composition lost: %+v", got.BackendGroups)
	}
	if len(got.ErrorPages) != 1 || got.ErrorPages[0].Status != "404" {
		t.Errorf("error pages lost: %+v", got.ErrorPages)
	}
	if !got.CORSEnabled || !got.CORSAllowCredentials || len(got.CORSAllowOrigins) != 2 {
		t.Errorf("CORS fields lost: enabled=%v creds=%v origins=%v", got.CORSEnabled, got.CORSAllowCredentials, got.CORSAllowOrigins)
	}
}

func TestListHostsByKind(t *testing.T) {
	st, ctx := newTestStore(t)
	mk := func(kind HostKind, dom string) {
		if err := st.CreateHost(ctx, &Host{Kind: kind, Domains: []string{dom}, TLS: TLSNone}); err != nil {
			t.Fatal(err)
		}
	}
	mk(HostKindProxy, "p1")
	mk(HostKindProxy, "p2")
	mk(HostKindStream, "s1")
	mk(HostKindRedirection, "r1")

	all, _ := st.ListHosts(ctx, "")
	if len(all) != 4 {
		t.Fatalf("ListHosts(all) = %d, want 4", len(all))
	}
	proxies, _ := st.ListHosts(ctx, HostKindProxy)
	if len(proxies) != 2 {
		t.Fatalf("ListHosts(proxy) = %d, want 2", len(proxies))
	}
	streams, _ := st.ListHosts(ctx, HostKindStream)
	if len(streams) != 1 || streams[0].Kind != HostKindStream {
		t.Fatalf("ListHosts(stream) = %+v", streams)
	}
}

func TestSettingsUpsert(t *testing.T) {
	st, ctx := newTestStore(t)
	if v, _ := st.GetSetting(ctx, "missing"); v != "" {
		t.Errorf("missing setting = %q, want empty", v)
	}
	if err := st.SetSetting(ctx, "ban.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.GetSetting(ctx, "ban.enabled"); v != "true" {
		t.Errorf("setting = %q, want true", v)
	}
	// Upsert (same key, new value).
	if err := st.SetSetting(ctx, "ban.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	if v, _ := st.GetSetting(ctx, "ban.enabled"); v != "false" {
		t.Errorf("upserted setting = %q, want false", v)
	}
	_ = st.SetSetting(ctx, "another", "x")
	all, err := st.ListAllSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if all["ban.enabled"] != "false" || all["another"] != "x" {
		t.Errorf("ListAllSettings = %v", all)
	}
}

func TestCertificateEncryptedFieldsRoundTrip(t *testing.T) {
	st, ctx := newTestStore(t)
	now := time.Now().Add(60 * 24 * time.Hour).UTC().Truncate(time.Second)
	c := &Certificate{
		Type:      CertTypeACME,
		Domains:   []string{"secure.example.com"},
		Status:    CertStatusValid,
		CertPEM:   "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		KeyPEMEnc: "encrypted-key-blob",
		ExpiresAt: &now,
		AutoRenew: true,
	}
	if err := st.CreateCertificate(ctx, c); err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	got, err := st.GetCertificate(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got.CertPEM != c.CertPEM || got.KeyPEMEnc != c.KeyPEMEnc {
		t.Error("PEM material not round-tripped")
	}
	if !got.AutoRenew || got.Status != CertStatusValid {
		t.Errorf("scalar fields lost: %+v", got)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(now) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, now)
	}
	// Nil ExpiresAt path.
	c2 := &Certificate{Type: CertTypeUploaded, Domains: []string{"x"}, Status: CertStatusPending}
	if err := st.CreateCertificate(ctx, c2); err != nil {
		t.Fatal(err)
	}
	got2, _ := st.GetCertificate(ctx, c2.ID)
	if got2.ExpiresAt != nil {
		t.Errorf("ExpiresAt should be nil, got %v", got2.ExpiresAt)
	}
}

func TestMiddlewareParamsRoundTrip(t *testing.T) {
	st, ctx := newTestStore(t)
	m := &Middleware{
		Name: "rl", Type: "rateLimit",
		Params: map[string]any{"average": float64(100), "burst": float64(50)},
	}
	if err := st.CreateMiddleware(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetMiddleware(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "rateLimit" || got.Params["average"] != float64(100) {
		t.Errorf("middleware params lost: %+v", got.Params)
	}
	list, _ := st.ListMiddlewares(ctx)
	if len(list) != 1 {
		t.Fatalf("ListMiddlewares = %d", len(list))
	}
	if err := st.DeleteMiddleware(ctx, m.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.ListMiddlewares(ctx); len(list) != 0 {
		t.Fatalf("middleware not deleted: %d remain", len(list))
	}
}

func TestAccessListRoundTrip(t *testing.T) {
	st, ctx := newTestStore(t)
	a := &AccessList{
		Name:       "team",
		Users:      []AccessListUser{{Username: "bob", Hash: "$2a$10$abc"}},
		AllowIPs:   []string{"10.0.0.0/8", "192.168.1.0/24"},
		SatisfyAny: true,
	}
	if err := st.CreateAccessList(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAccessList(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Users) != 1 || got.Users[0].Username != "bob" {
		t.Errorf("users lost: %+v", got.Users)
	}
	if len(got.AllowIPs) != 2 || !got.SatisfyAny {
		t.Errorf("ip/satisfy lost: %+v", got)
	}
}

func TestSnapshotsVersioningAndPrune(t *testing.T) {
	st, ctx := newTestStore(t)
	if v, _ := st.LatestSnapshotVersion(ctx); v != 0 {
		t.Fatalf("fresh LatestSnapshotVersion = %d, want 0", v)
	}
	for i := int64(1); i <= 5; i++ {
		if err := st.AddSnapshot(ctx, &ConfigSnapshot{Version: i, JSON: `{"v":` + string(rune('0'+i)) + `}`, Hash: "h", Valid: true}); err != nil {
			t.Fatalf("AddSnapshot %d: %v", i, err)
		}
	}
	if v, _ := st.LatestSnapshotVersion(ctx); v != 5 {
		t.Fatalf("LatestSnapshotVersion = %d, want 5", v)
	}
	snap, err := st.GetSnapshot(ctx, 3)
	if err != nil || snap.Version != 3 {
		t.Fatalf("GetSnapshot(3): %v / %+v", err, snap)
	}
	// Prune keeps only the newest 2.
	if err := st.PruneSnapshots(ctx, 2); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListSnapshots(ctx, 50)
	if len(list) != 2 {
		t.Fatalf("after prune ListSnapshots = %d, want 2", len(list))
	}
	if _, err := st.GetSnapshot(ctx, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("old snapshot still present: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	st, ctx := newTestStore(t)
	u := &User{Email: "s@x.com", Role: RoleViewer, PasswordHash: "h"}
	_ = st.CreateUser(ctx, u)

	live := &Session{Token: "tok-live", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	expired := &Session{Token: "tok-old", UserID: u.ID, ExpiresAt: time.Now().Add(-time.Hour)}
	if err := st.CreateSession(ctx, live); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, expired); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetSession(ctx, "tok-live")
	if err != nil || got.UserID != u.ID {
		t.Fatalf("GetSession(live): %v / %+v", err, got)
	}
	// Expired sessions must not be returned as valid.
	if _, err := st.GetSession(ctx, "tok-old"); err == nil {
		t.Error("expired session returned as valid")
	}
	// Purge removes expired rows.
	if err := st.PurgeExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	// Explicit delete (logout).
	if err := st.DeleteSession(ctx, "tok-live"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "tok-live"); err == nil {
		t.Error("session still valid after delete")
	}
}

// S7: the live token must never be stored verbatim — the DB holds only sha256(token),
// so a database read can't hand out usable sessions. Lookups by the live token still work.
func TestSessionTokenHashedAtRest(t *testing.T) {
	st, ctx := newTestStore(t)
	u := &User{Email: "h@x.com", Role: RoleViewer, PasswordHash: "h"}
	_ = st.CreateUser(ctx, u)

	const tok = "live-session-token-xyz"
	if err := st.CreateSession(ctx, &Session{Token: tok, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	var stored string
	if err := st.queryRow(ctx, `SELECT token FROM sessions WHERE user_id = ?`, u.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == tok {
		t.Fatal("session token stored verbatim at rest (must be hashed)")
	}
	if stored != hashSessionToken(tok) {
		t.Errorf("stored token = %q, want sha256(token) = %q", stored, hashSessionToken(tok))
	}
	// The live token still resolves the session, and its hash never leaks out.
	got, err := st.GetSession(ctx, tok)
	if err != nil {
		t.Fatalf("GetSession(live token): %v", err)
	}
	if got.Token != tok {
		t.Errorf("GetSession returned token %q, want the live token %q (not the hash)", got.Token, tok)
	}
}

func TestLeaseLeaderElection(t *testing.T) {
	st, ctx := newTestStore(t)
	// First holder takes the lease.
	ok, err := st.AcquireLease(ctx, "acme-renewal", "node-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("node-a acquire: ok=%v err=%v", ok, err)
	}
	// Second holder is denied while it's held and unexpired.
	ok, err = st.AcquireLease(ctx, "acme-renewal", "node-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("node-b acquired a lease held by node-a")
	}
	// The current holder can refresh.
	ok, _ = st.AcquireLease(ctx, "acme-renewal", "node-a", time.Minute)
	if !ok {
		t.Fatal("node-a could not refresh its own lease")
	}
	// An expired lease can be taken over.
	ok, _ = st.AcquireLease(ctx, "short", "node-a", -time.Second) // already expired
	if !ok {
		t.Fatal("initial acquire of 'short' failed")
	}
	ok, err = st.AcquireLease(ctx, "short", "node-b", time.Minute)
	if err != nil || !ok {
		t.Fatalf("node-b takeover of expired lease: ok=%v err=%v", ok, err)
	}
}

func TestBanStoreActiveAndPrune(t *testing.T) {
	st, ctx := newTestStore(t)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	if err := st.AddBan(ctx, &Ban{IP: "1.1.1.1", Reason: "manual", Manual: true}); err != nil { // permanent
		t.Fatal(err)
	}
	if err := st.AddBan(ctx, &Ban{IP: "2.2.2.2", ExpiresAt: &future}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddBan(ctx, &Ban{IP: "3.3.3.3", ExpiresAt: &past}); err != nil {
		t.Fatal(err)
	}

	active, err := st.ListActiveBans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 {
		t.Fatalf("ListActiveBans = %d, want 2 (permanent + future)", len(active))
	}
	if banned, _ := st.IsActivelyBanned(ctx, "1.1.1.1"); !banned {
		t.Error("permanent ban not active")
	}
	if banned, _ := st.IsActivelyBanned(ctx, "3.3.3.3"); banned {
		t.Error("expired ban reported active")
	}

	// Upsert: re-banning an IP updates rather than duplicating.
	if err := st.AddBan(ctx, &Ban{IP: "1.1.1.1", Reason: "updated", Hits: 9}); err != nil {
		t.Fatal(err)
	}
	active, _ = st.ListActiveBans(ctx)
	count := 0
	for _, b := range active {
		if b.IP == "1.1.1.1" {
			count++
			if b.Reason != "updated" || b.Hits != 9 {
				t.Errorf("ban upsert not applied: %+v", b)
			}
		}
	}
	if count != 1 {
		t.Fatalf("IP 1.1.1.1 appears %d times, want 1 (upsert)", count)
	}

	// Prune removes only expired rows.
	n, err := st.PruneExpiredBans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("PruneExpiredBans removed %d, want 1", n)
	}
	if err := st.DeleteBan(ctx, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if banned, _ := st.IsActivelyBanned(ctx, "1.1.1.1"); banned {
		t.Error("ban still active after delete")
	}
}

func TestAuditAppendAndList(t *testing.T) {
	st, ctx := newTestStore(t)
	for i := 0; i < 3; i++ {
		if err := st.AddAudit(ctx, &AuditEntry{UserEmail: "a@b.c", Action: "host.create", Target: "h" + string(rune('1'+i))}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("ListAudit = %d, want 3", len(list))
	}
	// Limit is honoured.
	limited, _ := st.ListAudit(ctx, 2)
	if len(limited) != 2 {
		t.Fatalf("ListAudit(2) = %d, want 2", len(limited))
	}
}

func TestSQLitePathDerivation(t *testing.T) {
	cfg := &config.Config{DataDir: "/tmp/data"}
	if got := cfg.SQLitePath(); got != filepath.Join("/tmp/data", "xgress.db") {
		t.Errorf("SQLitePath = %q", got)
	}
}

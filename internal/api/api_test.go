package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/engine"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/supervisor"
	"github.com/suckharder/xgress/internal/traefikcfg"
)

const testPassword = "password123"

func newTestAPI(t *testing.T) (*httptest.Server, *store.Store, context.Context) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:          dir,
		DBDriver:         config.DriverSQLite,
		HTTPEntryPoint:   "web",
		HTTPSEntryPoint:  "websecure",
		HTTPPort:         80,
		HTTPSPort:        443,
		TraefikStaticCfg: dir + "/traefik.yml", // so SyncStatic (plugins toggle) can write
		Dev:              true,                 // so the session cookie isn't marked Secure (httptest is plain HTTP)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatal(err)
	}
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: slog.Default()})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(cfg, st, box, sup, nil, "http://127.0.0.1:9000", logger)
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>xgress</title>")}}
	srv := NewServer(cfg, st, eng, box, assets, logger)
	ts := httptest.NewServer(srv.AdminHandler())
	t.Cleanup(ts.Close)
	return ts, st, ctx
}

// makeUser inserts a user with a known password and returns it.
func makeUser(t *testing.T, st *store.Store, ctx context.Context, email string, role store.Role) *store.User {
	t.Helper()
	hash, err := hashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{Email: email, Name: email, PasswordHash: hash, Role: role}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// loginClient returns an HTTP client with a cookie jar that has authenticated as
// the given credentials against the running test server.
func loginClient(t *testing.T, ts *httptest.Server, email string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	body, _ := json.Marshal(loginReq{Email: email, Password: testPassword})
	resp, err := c.Post(ts.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("login as %s failed: %d %s", email, resp.StatusCode, b)
	}
	return c
}

func do(t *testing.T, c *http.Client, method, url, body string) int {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestSetupFlowAndSelfDisable(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	c := &http.Client{}

	// Fresh store → needsSetup true.
	resp, _ := c.Get(ts.URL + "/api/setup")
	var status struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	json.NewDecoder(resp.Body).Decode(&status)
	resp.Body.Close()
	if !status.NeedsSetup {
		t.Fatal("fresh store should need setup")
	}

	// Create the first admin.
	body := `{"email":"admin@example.com","name":"Admin","password":"password123"}`
	if code := do(t, c, "POST", ts.URL+"/api/setup", body); code != http.StatusCreated {
		t.Fatalf("setup POST = %d, want 201", code)
	}
	if n, _ := st.CountUsers(ctx); n != 1 {
		t.Fatalf("user count after setup = %d, want 1", n)
	}

	// Setup self-disables once a user exists.
	if code := do(t, c, "POST", ts.URL+"/api/setup", body); code != http.StatusConflict {
		t.Fatalf("second setup = %d, want 409", code)
	}
	// And needsSetup flips to false.
	resp, _ = c.Get(ts.URL + "/api/setup")
	json.NewDecoder(resp.Body).Decode(&status)
	resp.Body.Close()
	if status.NeedsSetup {
		t.Fatal("needsSetup should be false after setup")
	}
}

func TestSetupRejectsWeakInput(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	c := &http.Client{}
	// Short password.
	if code := do(t, c, "POST", ts.URL+"/api/setup", `{"email":"a@b.c","password":"short"}`); code != http.StatusBadRequest {
		t.Errorf("weak password = %d, want 400", code)
	}
	// Missing @ in email.
	if code := do(t, c, "POST", ts.URL+"/api/setup", `{"email":"nope","password":"password123"}`); code != http.StatusBadRequest {
		t.Errorf("bad email = %d, want 400", code)
	}
}

func TestLoginSuccessAndFailure(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "user@example.com", store.RoleAdmin)
	c := &http.Client{}

	// Wrong password.
	if code := do(t, c, "POST", ts.URL+"/api/login", `{"email":"user@example.com","password":"wrong"}`); code != http.StatusUnauthorized {
		t.Errorf("wrong password = %d, want 401", code)
	}
	// Unknown user.
	if code := do(t, c, "POST", ts.URL+"/api/login", `{"email":"ghost@example.com","password":"password123"}`); code != http.StatusUnauthorized {
		t.Errorf("unknown user = %d, want 401", code)
	}
	// Correct credentials succeed and set a session usable on /api/me.
	cl := loginClient(t, ts, "user@example.com")
	if code := do(t, cl, "GET", ts.URL+"/api/me", ""); code != http.StatusOK {
		t.Errorf("authed /api/me = %d, want 200", code)
	}
}

func TestMeRequiresAuth(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	c := &http.Client{}
	if code := do(t, c, "GET", ts.URL+"/api/me", ""); code != http.StatusUnauthorized {
		t.Errorf("unauth /api/me = %d, want 401", code)
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	c := loginClient(t, ts, "admin@example.com")
	if code := do(t, c, "GET", ts.URL+"/api/me", ""); code != http.StatusOK {
		t.Fatal("should be authed before logout")
	}
	if code := do(t, c, "POST", ts.URL+"/api/logout", ""); code != http.StatusOK {
		t.Fatalf("logout = %d", code)
	}
	if code := do(t, c, "GET", ts.URL+"/api/me", ""); code != http.StatusUnauthorized {
		t.Errorf("/api/me after logout = %d, want 401", code)
	}
}

// TestRBACMatrix is the core authorization test: it checks that each role gets
// the expected status on a representative set of read / operator / admin routes.
func TestRBACMatrix(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	makeUser(t, st, ctx, "op@example.com", store.RoleOperator)
	makeUser(t, st, ctx, "viewer@example.com", store.RoleViewer)

	clients := map[string]*http.Client{
		"unauth":   {},
		"viewer":   loginClient(t, ts, "viewer@example.com"),
		"operator": loginClient(t, ts, "op@example.com"),
		"admin":    loginClient(t, ts, "admin@example.com"),
	}

	// Read-only and admin-only GET/idempotent routes — safe to probe with every
	// role repeatedly (no shared-state mutation hazards).
	type tc struct {
		name               string
		method, path, body string
		want               map[string]int
	}
	cases := []tc{
		{
			name: "read hosts (ro)", method: "GET", path: "/api/hosts",
			want: map[string]int{"unauth": 401, "viewer": 200, "operator": 200, "admin": 200},
		},
		{
			name: "read bans config (ro)", method: "GET", path: "/api/bans-config",
			want: map[string]int{"unauth": 401, "viewer": 200, "operator": 200, "admin": 200},
		},
		{
			name: "read settings (ro)", method: "GET", path: "/api/settings",
			want: map[string]int{"unauth": 401, "viewer": 200, "operator": 200, "admin": 200},
		},
		{
			name: "list users (admin only)", method: "GET", path: "/api/users",
			want: map[string]int{"unauth": 401, "viewer": 403, "operator": 403, "admin": 200},
		},
		{
			name: "set settings (admin only, idempotent)", method: "PUT", path: "/api/settings", body: `{}`,
			want: map[string]int{"unauth": 401, "viewer": 403, "operator": 403, "admin": 200},
		},
		{
			name: "backup export (admin only)", method: "GET", path: "/api/backup",
			want: map[string]int{"unauth": 401, "viewer": 403, "operator": 403, "admin": 200},
		},
		{
			name: "notifications (admin only)", method: "GET", path: "/api/notifications",
			want: map[string]int{"unauth": 401, "viewer": 403, "operator": 403, "admin": 200},
		},
	}

	for _, c := range cases {
		for role, want := range c.want {
			got := do(t, clients[role], c.method, ts.URL+c.path, c.body)
			if got != want {
				t.Errorf("%s [%s]: got %d, want %d", c.name, role, got, want)
			}
		}
	}
}

// TestOperatorMutationBoundary verifies the operator/viewer split on a mutating
// proxy-config route, using unique domains per call to avoid conflicts.
func TestOperatorMutationBoundary(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "op@example.com", store.RoleOperator)
	makeUser(t, st, ctx, "viewer@example.com", store.RoleViewer)
	op := loginClient(t, ts, "op@example.com")
	viewer := loginClient(t, ts, "viewer@example.com")
	unauth := &http.Client{}

	host := func(dom string) string {
		return `{"kind":"proxy","enabled":true,"domains":["` + dom + `"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`
	}
	// Operator can create.
	if code := do(t, op, "POST", ts.URL+"/api/hosts", host("op.example.com")); code != http.StatusCreated {
		t.Errorf("operator create host = %d, want 201", code)
	}
	// Viewer is forbidden (before the handler runs).
	if code := do(t, viewer, "POST", ts.URL+"/api/hosts", host("viewer.example.com")); code != http.StatusForbidden {
		t.Errorf("viewer create host = %d, want 403", code)
	}
	// Unauthenticated is rejected at the auth layer.
	if code := do(t, unauth, "POST", ts.URL+"/api/hosts", host("anon.example.com")); code != http.StatusUnauthorized {
		t.Errorf("unauth create host = %d, want 401", code)
	}
	// Only the operator's host should have been persisted.
	hosts, _ := st.ListHosts(ctx, "")
	if len(hosts) != 1 || hosts[0].Domains[0] != "op.example.com" {
		t.Fatalf("expected exactly the operator host to persist, got %+v", hosts)
	}
}

func TestCreateBanReturns201(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "op@example.com", store.RoleOperator)
	c := loginClient(t, ts, "op@example.com")
	if code := do(t, c, "POST", ts.URL+"/api/bans", `{"ip":"198.51.100.22","durationSec":300}`); code != http.StatusCreated {
		t.Errorf("create ban = %d, want 201", code)
	}
	// Invalid IP is rejected with 400.
	if code := do(t, c, "POST", ts.URL+"/api/bans", `{"ip":"garbage"}`); code != http.StatusBadRequest {
		t.Errorf("invalid ban ip = %d, want 400", code)
	}
}

func TestUnknownAPIPathReturns404JSON(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/api/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown API path = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("404 content-type = %q, want JSON", ct)
	}
}

func TestSPAServedForClientRoutes(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/some/client/route")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SPA route = %d, want 200", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "<!doctype html>") {
		t.Errorf("SPA did not serve index.html: %q", b)
	}
}

func TestCORSValidation(t *testing.T) {
	proxy := func() *store.Host {
		return &store.Host{
			Kind: store.HostKindProxy, Domains: []string{"api.example.com"},
			Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		}
	}
	hasField := func(issues []traefikcfg.ValidationIssue, field string) bool {
		for _, i := range issues {
			if i.Field == field {
				return true
			}
		}
		return false
	}

	// CORS off → no CORS issues.
	if iss := validateHost(proxy()); hasField(iss, "corsAllowOrigins") {
		t.Errorf("unexpected CORS issue when disabled: %+v", iss)
	}

	// Enabled with no origins → issue.
	h := proxy()
	h.CORSEnabled = true
	if iss := validateHost(h); !hasField(iss, "corsAllowOrigins") {
		t.Error("expected an issue: CORS enabled with no origins")
	}

	// Enabled with a blank-only origin → still an issue.
	h = proxy()
	h.CORSEnabled = true
	h.CORSAllowOrigins = []string{"   "}
	if iss := validateHost(h); !hasField(iss, "corsAllowOrigins") {
		t.Error("expected an issue: CORS enabled with only blank origins")
	}

	// Credentials + wildcard → issue.
	h = proxy()
	h.CORSEnabled = true
	h.CORSAllowOrigins = []string{"*"}
	h.CORSAllowCredentials = true
	if iss := validateHost(h); !hasField(iss, "corsAllowOrigins") {
		t.Error("expected an issue: wildcard origin with credentials")
	}

	// Valid config → no CORS issue.
	h = proxy()
	h.CORSEnabled = true
	h.CORSAllowOrigins = []string{"https://app.example.com"}
	h.CORSAllowCredentials = true
	if iss := validateHost(h); hasField(iss, "corsAllowOrigins") {
		t.Errorf("unexpected CORS issue for valid config: %+v", iss)
	}
}

func TestProviderTokenGate(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: dir, DBDriver: config.DriverSQLite,
		HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure",
		ProviderToken: "s3cr3t-provider-token",
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.Load(dir + "/secret.key")
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: slog.Default()})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(cfg, st, box, sup, nil, "http://127.0.0.1:9000", logger)
	srv := NewServer(cfg, st, eng, box, fstest.MapFS{}, logger)
	ts := httptest.NewServer(srv.ProviderHandler())
	t.Cleanup(ts.Close)

	get := func(path, token string) int {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		if token != "" {
			req.Header.Set(config.ProviderTokenHeader, token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if code := get("/api/provider", ""); code != http.StatusUnauthorized {
		t.Errorf("no token = %d, want 401", code)
	}
	if code := get("/api/provider", "wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token = %d, want 401", code)
	}
	if code := get("/api/provider", "s3cr3t-provider-token"); code != http.StatusOK {
		t.Errorf("correct token = %d, want 200", code)
	}
	// /healthz is never gated.
	if code := get("/healthz", ""); code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", code)
	}
}

func TestProviderNoTokenServesOpen(t *testing.T) {
	// With ProviderToken unset, the endpoint is ungated (legacy behavior).
	dir := t.TempDir()
	cfg := &config.Config{DataDir: dir, DBDriver: config.DriverSQLite, HTTPEntryPoint: "web", HTTPSEntryPoint: "websecure"}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, _ := secrets.Load(dir + "/secret.key")
	sup := supervisor.New(supervisor.Options{Managed: false, Logger: slog.Default()})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := engine.New(cfg, st, box, sup, nil, "http://127.0.0.1:9000", logger)
	srv := NewServer(cfg, st, eng, box, fstest.MapFS{}, logger)
	ts := httptest.NewServer(srv.ProviderHandler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/api/provider")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ungated provider = %d, want 200", resp.StatusCode)
	}
}

func TestRawYAMLAdminGate(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	makeUser(t, st, ctx, "op@example.com", store.RoleOperator)
	adminC := loginClient(t, ts, "admin@example.com")
	opC := loginClient(t, ts, "op@example.com")

	mwRaw := "http:\n  middlewares:\n    m1:\n      headers:\n        customRequestHeaders:\n          X-T: \"1\"\n"
	routerRaw := "http:\n  routers:\n    x:\n      rule: \"PathPrefix(`/`)\"\n      service: s\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: \"http://10.0.0.2\"\n"
	body := func(dom, raw string) string {
		b, _ := json.Marshal(map[string]any{
			"kind": "proxy", "enabled": true, "domains": []string{dom},
			"upstreams": []map[string]any{{"scheme": "http", "host": "10.0.0.1", "port": 80}},
			"tls":       "none", "rawYaml": raw,
		})
		return string(b)
	}

	// Operator setting rawYaml → 403 (admin-gated).
	if code := do(t, opC, "POST", ts.URL+"/api/hosts", body("op1.example.com", mwRaw)); code != http.StatusForbidden {
		t.Errorf("operator set rawYaml = %d, want 403", code)
	}
	// Admin setting middleware-only rawYaml → 201.
	if code := do(t, adminC, "POST", ts.URL+"/api/hosts", body("ad1.example.com", mwRaw)); code != http.StatusCreated {
		t.Errorf("admin set middleware rawYaml = %d, want 201", code)
	}
	// Admin setting rawYaml that defines a ROUTER → 400 (per-host raw = mw/services only).
	if code := do(t, adminC, "POST", ts.URL+"/api/hosts", body("ad2.example.com", routerRaw)); code != http.StatusBadRequest {
		t.Errorf("admin set router rawYaml = %d, want 400", code)
	}

	// An existing raw-bearing host: operator may edit other fields (raw preserved),
	// but may not change the raw.
	h := &store.Host{
		Kind: store.HostKindProxy, Enabled: true, Domains: []string{"pre.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone,
		RawYAML: mwRaw,
	}
	if err := st.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Operator update omitting rawYaml → 200, raw preserved.
	upd, _ := json.Marshal(map[string]any{
		"kind": "proxy", "enabled": false, "domains": []string{"pre.example.com"},
		"upstreams": []map[string]any{{"scheme": "http", "host": "10.0.0.1", "port": 80}}, "tls": "none",
	})
	if code := do(t, opC, "PUT", ts.URL+"/api/hosts/"+h.ID, string(upd)); code != http.StatusOK {
		t.Errorf("operator edit (no raw) = %d, want 200", code)
	}
	got, _ := st.GetHost(ctx, h.ID)
	if got.RawYAML != mwRaw {
		t.Errorf("operator edit cleared rawYaml; want preserved")
	}
	// Operator changing the raw → 403.
	chg, _ := json.Marshal(map[string]any{
		"kind": "proxy", "enabled": true, "domains": []string{"pre.example.com"},
		"upstreams": []map[string]any{{"scheme": "http", "host": "10.0.0.1", "port": 80}}, "tls": "none",
		"rawYaml": mwRaw + "    X-T2: \"2\"\n",
	})
	if code := do(t, opC, "PUT", ts.URL+"/api/hosts/"+h.ID, string(chg)); code != http.StatusForbidden {
		t.Errorf("operator change rawYaml = %d, want 403", code)
	}
}

func TestSecurityHeadersIncludeCSP(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q; got %q", want, csp)
		}
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

func TestRecovererCatchesPanic(t *testing.T) {
	srv := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := srv.recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("recoverer returned %d, want 500", rec.Code)
	}
}

func TestNotifyRejectsSSRFTargets(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	adminC := loginClient(t, ts, "admin@example.com")

	// Webhook aimed at the loopback provider → 400.
	if code := do(t, adminC, "PUT", ts.URL+"/api/notifications", `{"webhookUrl":"http://127.0.0.1:9000/api/provider"}`); code != http.StatusBadRequest {
		t.Errorf("loopback webhook = %d, want 400", code)
	}
	// SMTP host = cloud metadata → 400.
	if code := do(t, adminC, "PUT", ts.URL+"/api/notifications", `{"smtpHost":"169.254.169.254"}`); code != http.StatusBadRequest {
		t.Errorf("metadata smtp = %d, want 400", code)
	}
	// A private webhook target is allowed (self-hosted) → 200.
	if code := do(t, adminC, "PUT", ts.URL+"/api/notifications", `{"webhookUrl":"http://10.0.0.5/hook"}`); code != http.StatusOK {
		t.Errorf("private webhook = %d, want 200", code)
	}
}

func TestRestoreValidatesAndAllowlistsSettings(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	adminC := loginClient(t, ts, "admin@example.com")

	// Seed an existing host that must survive a rejected restore.
	keep := &store.Host{Kind: store.HostKindProxy, Enabled: true, Domains: []string{"keep.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}}, TLS: store.TLSNone}
	if err := st.CreateHost(ctx, keep); err != nil {
		t.Fatal(err)
	}

	// A backup carrying an abusive host (raw router) must be REJECTED before any wipe.
	badHost := map[string]any{
		"kind": "proxy", "enabled": true, "domains": []string{"bad.example.com"},
		"upstreams": []map[string]any{{"scheme": "http", "host": "10.0.0.1", "port": 80}}, "tls": "none",
		"rawYaml": "http:\n  routers:\n    x:\n      rule: \"PathPrefix(`/`)\"\n      service: s\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: \"http://10.0.0.2\"\n",
	}
	bad, _ := json.Marshal(map[string]any{"version": 1, "hosts": []any{badHost}, "settings": map[string]string{}})
	if code := do(t, adminC, "POST", ts.URL+"/api/restore", string(bad)); code != http.StatusBadRequest {
		t.Errorf("restore of abusive host = %d, want 400", code)
	}
	hosts, _ := st.ListHosts(ctx, "")
	if len(hosts) != 1 || hosts[0].Domains[0] != "keep.example.com" {
		t.Fatalf("rejected restore wiped existing config: %+v", hosts)
	}

	// A valid backup applies allow-listed settings and ignores unknown ones.
	ok, _ := json.Marshal(map[string]any{"version": 1, "hosts": []any{},
		"settings": map[string]string{"evil.key": "x", "ban.enabled": "true"}})
	if code := do(t, adminC, "POST", ts.URL+"/api/restore", string(ok)); code != http.StatusOK {
		t.Errorf("valid restore = %d, want 200", code)
	}
	if v, _ := st.GetSetting(ctx, "evil.key"); v != "" {
		t.Error("unknown setting was applied (allow-list bypassed)")
	}
	if v, _ := st.GetSetting(ctx, "ban.enabled"); v != "true" {
		t.Error("allow-listed setting not applied")
	}
}

func TestBodyLimitRejectsOversizedBody(t *testing.T) {
	ts, _, _ := newTestAPI(t)
	body := `{"email":"a@b.c","password":"` + strings.Repeat("x", 17<<20) + `"}` // > 16 MB limit
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // connection closed by the body limit — acceptable
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		t.Errorf("oversized body accepted (%d); MaxBytesReader limit not enforced", resp.StatusCode)
	}
}

func TestClientIPIgnoresXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.5:54321"
	r.Header.Set("X-Forwarded-For", "1.2.3.4") // must be ignored for the audit trail
	if ip := clientIP(r); ip != "203.0.113.5" {
		t.Errorf("clientIP = %q, want 203.0.113.5 (X-Forwarded-For must not be trusted)", ip)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "rl@example.com", store.RoleAdmin)
	bad := `{"email":"rl@example.com","password":"wrong"}`
	for i := 0; i < 10; i++ {
		if code := do(t, &http.Client{}, "POST", ts.URL+"/api/login", bad); code != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d = %d, want 401", i, code)
		}
	}
	if code := do(t, &http.Client{}, "POST", ts.URL+"/api/login", bad); code != http.StatusTooManyRequests {
		t.Errorf("11th failed attempt = %d, want 429", code)
	}
	// Correct credentials are also refused while locked out.
	good := `{"email":"rl@example.com","password":"password123"}`
	if code := do(t, &http.Client{}, "POST", ts.URL+"/api/login", good); code != http.StatusTooManyRequests {
		t.Errorf("correct login during lockout = %d, want 429", code)
	}
}

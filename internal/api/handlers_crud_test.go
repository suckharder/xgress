package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/store"
)

// call performs an authenticated request and returns the status + body.
func call(t *testing.T, c *http.Client, method, url, body string) (int, []byte) {
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
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// adminAPI spins up the test server with a logged-in admin client.
func adminAPI(t *testing.T) (*httptest.Server, *store.Store, *http.Client) {
	t.Helper()
	ts, st, ctx := newTestAPI(t)
	makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	return ts, st, loginClient(t, ts, "admin@example.com")
}

// idOf extracts the "id" field from a JSON object body.
func idOf(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode id: %v (%s)", err, body)
	}
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatalf("no id in response: %s", body)
	}
	return id
}

func TestHostCRUDLifecycle(t *testing.T) {
	ts, _, c := adminAPI(t)
	host := `{"kind":"proxy","enabled":true,"domains":["app.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`

	code, body := call(t, c, "POST", ts.URL+"/api/hosts", host)
	if code != http.StatusCreated {
		t.Fatalf("create = %d: %s", code, body)
	}
	id := idOf(t, body)

	if code, _ := call(t, c, "GET", ts.URL+"/api/hosts/"+id, ""); code != http.StatusOK {
		t.Errorf("get = %d", code)
	}
	if code, b := call(t, c, "GET", ts.URL+"/api/hosts", ""); code != http.StatusOK || !strings.Contains(string(b), "app.example.com") {
		t.Errorf("list = %d: %s", code, b)
	}

	upd := `{"kind":"proxy","enabled":false,"domains":["app2.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.2","port":8080}],"tls":"none"}`
	if code, b := call(t, c, "PUT", ts.URL+"/api/hosts/"+id, upd); code != http.StatusOK {
		t.Errorf("update = %d: %s", code, b)
	}

	if code, _ := call(t, c, "DELETE", ts.URL+"/api/hosts/"+id, ""); code != http.StatusOK {
		t.Errorf("delete = %d", code)
	}
	if code, _ := call(t, c, "GET", ts.URL+"/api/hosts/"+id, ""); code != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", code)
	}
}

func TestHostValidationErrors(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Proxy with no domains/upstreams → 400 validation issues.
	if code, b := call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","tls":"none"}`); code != http.StatusBadRequest || !strings.Contains(string(b), "validation failed") {
		t.Errorf("invalid host = %d: %s", code, b)
	}
	// Malformed JSON body → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/hosts", `{not json`); code != http.StatusBadRequest {
		t.Errorf("bad json = %d, want 400", code)
	}
	// Get/update/delete of an unknown id.
	if code, _ := call(t, c, "GET", ts.URL+"/api/hosts/nope", ""); code != http.StatusNotFound {
		t.Errorf("get unknown = %d, want 404", code)
	}
	if code, _ := call(t, c, "PUT", ts.URL+"/api/hosts/nope", `{"kind":"proxy"}`); code != http.StatusNotFound {
		t.Errorf("update unknown = %d, want 404", code)
	}
}

func TestMiddlewareCRUD(t *testing.T) {
	ts, _, c := adminAPI(t)
	create := `{"name":"rl","type":"rateLimit","params":{"average":100,"burst":20}}`
	code, body := call(t, c, "POST", ts.URL+"/api/middlewares", create)
	if code != http.StatusCreated {
		t.Fatalf("create mw = %d: %s", code, body)
	}
	id := idOf(t, body)

	if code, b := call(t, c, "GET", ts.URL+"/api/middlewares", ""); code != http.StatusOK || !strings.Contains(string(b), "rateLimit") {
		t.Errorf("list mw = %d: %s", code, b)
	}
	upd := `{"name":"rl","type":"rateLimit","params":{"average":50,"burst":5}}`
	if code, _ := call(t, c, "PUT", ts.URL+"/api/middlewares/"+id, upd); code != http.StatusOK {
		t.Errorf("update mw = %d", code)
	}
	// Invalid params (unknown field) → 400.
	if code, _ := call(t, c, "PUT", ts.URL+"/api/middlewares/"+id, `{"type":"headers","params":{"nope":1}}`); code != http.StatusBadRequest {
		t.Errorf("invalid update = %d, want 400", code)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/middlewares/"+id, ""); code != http.StatusOK {
		t.Errorf("delete mw = %d", code)
	}
	// Catalog endpoint.
	if code, b := call(t, c, "GET", ts.URL+"/api/middleware-catalog", ""); code != http.StatusOK || !strings.Contains(string(b), "basicAuth") {
		t.Errorf("catalog = %d: %s", code, b)
	}
	// Create with an invalid type → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/middlewares", `{"type":"headers","params":{"bogus":true}}`); code != http.StatusBadRequest {
		t.Errorf("invalid create = %d, want 400", code)
	}
}

func TestCertificateUploadedLifecycle(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Uploaded cert is synchronous (no ACME) — safe to test end to end.
	create := `{"type":"uploaded","domains":["cert.example.com"],"certPem":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----","keyPem":"-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----"}`
	code, body := call(t, c, "POST", ts.URL+"/api/certificates", create)
	if code != http.StatusCreated {
		t.Fatalf("create cert = %d: %s", code, body)
	}
	id := idOf(t, body)

	if code, b := call(t, c, "GET", ts.URL+"/api/certificates", ""); code != http.StatusOK || !strings.Contains(string(b), "cert.example.com") {
		t.Errorf("list certs = %d: %s", code, b)
	}
	// A non-ACME cert cannot be renewed → 400 (and never reaches async issuance).
	if code, _ := call(t, c, "POST", ts.URL+"/api/certificates/"+id+"/renew", ""); code != http.StatusBadRequest {
		t.Errorf("renew uploaded = %d, want 400", code)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/certificates/"+id, ""); code != http.StatusOK {
		t.Errorf("delete cert = %d", code)
	}
}

func TestCertificateValidation(t *testing.T) {
	ts, _, c := adminAPI(t)
	// No domains → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/certificates", `{"type":"uploaded"}`); code != http.StatusBadRequest {
		t.Errorf("no domains = %d, want 400", code)
	}
	// Uploaded without PEMs → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/certificates", `{"type":"uploaded","domains":["x.example.com"]}`); code != http.StatusBadRequest {
		t.Errorf("uploaded no pem = %d, want 400", code)
	}
	// Unknown type → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/certificates", `{"type":"bogus","domains":["x.example.com"]}`); code != http.StatusBadRequest {
		t.Errorf("unknown type = %d, want 400", code)
	}
}

func TestAccessListCRUDAndHtpasswd(t *testing.T) {
	ts, _, c := adminAPI(t)
	create := `{"name":"team","users":[{"username":"alice","password":"s3cret-pass"}],"allowIps":["10.0.0.0/8"," "]}`
	code, body := call(t, c, "POST", ts.URL+"/api/access-lists", create)
	if code != http.StatusCreated {
		t.Fatalf("create acl = %d: %s", code, body)
	}
	// The plaintext password must never round-trip back; a hash is stored.
	if strings.Contains(string(body), "s3cret-pass") {
		t.Error("access-list response leaked the plaintext password")
	}
	id := idOf(t, body)

	if code, b := call(t, c, "GET", ts.URL+"/api/access-lists", ""); code != http.StatusOK || !strings.Contains(string(b), "team") {
		t.Errorf("list acl = %d: %s", code, b)
	}
	upd := `{"name":"team2","users":[{"username":"bob","password":"another-pass"}],"allowIps":["192.168.0.0/16"]}`
	if code, _ := call(t, c, "PUT", ts.URL+"/api/access-lists/"+id, upd); code != http.StatusOK {
		t.Errorf("update acl = %d", code)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/access-lists/"+id, ""); code != http.StatusOK {
		t.Errorf("delete acl = %d", code)
	}
	// Missing name → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/access-lists", `{"users":[]}`); code != http.StatusBadRequest {
		t.Errorf("acl no name = %d, want 400", code)
	}
	// Invalid IP/CIDR in the allow list → 400. Closes the satisfy-any ClientIP()
	// injection and prevents a malformed ipAllowList middleware build.
	if code, b := call(t, c, "POST", ts.URL+"/api/access-lists", `{"name":"x","allowIps":["not-an-ip"]}`); code != http.StatusBadRequest {
		t.Errorf("acl invalid CIDR = %d, want 400: %s", code, b)
	}
	// A rule-injection payload in allowIps is rejected (it isn't a valid IP/CIDR).
	injACL := `{"name":"y","allowIps":["1.2.3.4` + "`" + `) || ClientIP(` + "`" + `0.0.0.0/0"]}`
	if code, _ := call(t, c, "POST", ts.URL+"/api/access-lists", injACL); code != http.StatusBadRequest {
		t.Errorf("acl injection payload should be rejected, got %d", code)
	}
	// htpasswd helper.
	code, b := call(t, c, "POST", ts.URL+"/api/util/htpasswd", `{"username":"u","password":"p"}`)
	if code != http.StatusOK || !strings.Contains(string(b), "u:$2") {
		t.Errorf("htpasswd = %d: %s", code, b)
	}
	if code, _ := call(t, c, "POST", ts.URL+"/api/util/htpasswd", `{"username":"u"}`); code != http.StatusBadRequest {
		t.Errorf("htpasswd no pass = %d, want 400", code)
	}
}

func TestDNSProviderCRUD(t *testing.T) {
	ts, _, c := adminAPI(t)
	create := `{"name":"cf","provider":"cloudflare","config":{"CF_DNS_API_TOKEN":"tok-secret"}}`
	code, body := call(t, c, "POST", ts.URL+"/api/dns-providers", create)
	if code != http.StatusCreated {
		t.Fatalf("create dns = %d: %s", code, body)
	}
	// Credential value must be encrypted, never echoed.
	if strings.Contains(string(body), "tok-secret") {
		t.Error("DNS provider response leaked the credential")
	}
	id := idOf(t, body)
	if code, b := call(t, c, "GET", ts.URL+"/api/dns-providers", ""); code != http.StatusOK || !strings.Contains(string(b), "cloudflare") {
		t.Errorf("list dns = %d: %s", code, b)
	}
	if code, b := call(t, c, "GET", ts.URL+"/api/dns-catalog", ""); code != http.StatusOK || len(b) < 3 {
		t.Errorf("dns catalog = %d", code)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/dns-providers/"+id, ""); code != http.StatusOK {
		t.Errorf("delete dns = %d", code)
	}
	// Missing fields → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/dns-providers", `{"name":"x"}`); code != http.StatusBadRequest {
		t.Errorf("dns no provider = %d, want 400", code)
	}
}

func TestBanManagementAndConfig(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Manual ban (CIDR), then list, then delete via path.
	if code, _ := call(t, c, "POST", ts.URL+"/api/bans", `{"ip":"10.0.0.0/8","reason":"abuse","durationSec":0}`); code != http.StatusCreated {
		t.Errorf("create CIDR ban = %d", code)
	}
	if code, b := call(t, c, "GET", ts.URL+"/api/bans", ""); code != http.StatusOK || !strings.Contains(string(b), "10.0.0.0/8") {
		t.Errorf("list bans = %d: %s", code, b)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/bans/10.0.0.0/8", ""); code != http.StatusOK {
		t.Errorf("delete ban = %d", code)
	}
	// Ban config round-trip: enable auto-ban with custom thresholds.
	if code, b := call(t, c, "GET", ts.URL+"/api/bans-config", ""); code != http.StatusOK {
		t.Errorf("get ban config = %d: %s", code, b)
	}
	code, b := call(t, c, "PUT", ts.URL+"/api/bans-config", `{"enabled":true,"threshold":5,"windowSec":60,"durationSec":3600}`)
	if code != http.StatusOK || !strings.Contains(string(b), `"enabled":true`) {
		t.Errorf("set ban config = %d: %s", code, b)
	}
}

func TestDefaultSiteAndRawConfig(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Default site defaults then update.
	if code, b := call(t, c, "GET", ts.URL+"/api/default-site", ""); code != http.StatusOK || !strings.Contains(string(b), `"mode":"404"`) {
		t.Errorf("get default-site = %d: %s", code, b)
	}
	if code, _ := call(t, c, "PUT", ts.URL+"/api/default-site", `{"mode":"redirect","redirectTo":"https://example.com"}`); code != http.StatusOK {
		t.Errorf("set default-site = %d", code)
	}
	// Raw config: empty get, valid set, then an invalid snippet rejected pre-persist.
	if code, _ := call(t, c, "GET", ts.URL+"/api/raw-config", ""); code != http.StatusOK {
		t.Errorf("get raw = %d", code)
	}
	validRaw := `{"yaml":"http:\n  middlewares:\n    extra:\n      compress: {}\n"}`
	if code, b := call(t, c, "PUT", ts.URL+"/api/raw-config", validRaw); code != http.StatusOK {
		t.Errorf("set valid raw = %d: %s", code, b)
	}
	// A raw service aimed at a loopback target is rejected (SSRF guard) → 422.
	ssrfRaw := `{"yaml":"http:\n  services:\n    s:\n      loadBalancer:\n        servers:\n          - url: \"http://127.0.0.1:9000\"\n"}`
	if code, _ := call(t, c, "PUT", ts.URL+"/api/raw-config", ssrfRaw); code != http.StatusUnprocessableEntity {
		t.Errorf("set ssrf raw = %d, want 422", code)
	}
	// Garbage YAML → 422.
	if code, _ := call(t, c, "PUT", ts.URL+"/api/raw-config", `{"yaml":"http:\n  routers:\n    : bad"}`); code != http.StatusUnprocessableEntity {
		t.Errorf("set bad raw = %d, want 422", code)
	}
}

func TestPluginsToggle(t *testing.T) {
	ts, _, c := adminAPI(t)
	if code, b := call(t, c, "GET", ts.URL+"/api/plugins", ""); code != http.StatusOK || !strings.Contains(string(b), "wafParanoia") {
		t.Errorf("get plugins = %d: %s", code, b)
	}
	// Native WAF: set paranoia/anomaly + cache on. Pure hot-reload (no Traefik restart).
	set := `{"wafEnabled":true,"wafParanoia":2,"wafAnomaly":7,"wafDirectives":[],"cacheEnabled":true}`
	if code, b := call(t, c, "PUT", ts.URL+"/api/plugins", set); code != http.StatusOK {
		t.Errorf("set plugins = %d: %s", code, b)
	}
	// A malformed custom seclang directive is rejected (422) BEFORE it is persisted.
	bad := `{"wafEnabled":true,"wafDirectives":["TotallyNotADirective foo"]}`
	if code, b := call(t, c, "PUT", ts.URL+"/api/plugins", bad); code != http.StatusUnprocessableEntity {
		t.Errorf("malformed WAF directive should be 422, got %d: %s", code, b)
	}
	if code, b := call(t, c, "GET", ts.URL+"/api/security/metrics", ""); code != http.StatusOK || !strings.Contains(string(b), "wafEnabled") {
		t.Errorf("security metrics = %d: %s", code, b)
	}
}

func TestScheduleCRUD(t *testing.T) {
	ts, _, c := adminAPI(t)
	_, hb := call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","enabled":true,"domains":["s.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`)
	hid := idOf(t, hb)

	code, sb := call(t, c, "POST", ts.URL+"/api/hosts/"+hid+"/schedules", `{"action":"disable","cron":"0 22 * * *"}`)
	if code != http.StatusCreated {
		t.Fatalf("create schedule = %d: %s", code, sb)
	}
	sid := idOf(t, sb)
	if code, b := call(t, c, "GET", ts.URL+"/api/hosts/"+hid+"/schedules", ""); code != http.StatusOK || !strings.Contains(string(b), "disable") {
		t.Errorf("list schedules = %d: %s", code, b)
	}
	// Bad action / bad cron → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/hosts/"+hid+"/schedules", `{"action":"explode","cron":"0 22 * * *"}`); code != http.StatusBadRequest {
		t.Errorf("bad action = %d, want 400", code)
	}
	if code, _ := call(t, c, "POST", ts.URL+"/api/hosts/"+hid+"/schedules", `{"action":"enable","cron":"nope"}`); code != http.StatusBadRequest {
		t.Errorf("bad cron = %d, want 400", code)
	}
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/schedules/"+sid, ""); code != http.StatusOK {
		t.Errorf("delete schedule = %d", code)
	}
}

func TestUserManagement(t *testing.T) {
	ts, st, c := adminAPI(t)
	create := `{"email":"new@example.com","name":"New","password":"password123","role":"operator"}`
	code, body := call(t, c, "POST", ts.URL+"/api/users", create)
	if code != http.StatusCreated {
		t.Fatalf("create user = %d: %s", code, body)
	}
	// Password hash must never be serialized to the client.
	if strings.Contains(string(body), "password123") || strings.Contains(strings.ToLower(string(body)), "passwordhash") {
		t.Error("user response leaked password material")
	}
	id := idOf(t, body)

	if code, b := call(t, c, "GET", ts.URL+"/api/users", ""); code != http.StatusOK || !strings.Contains(string(b), "new@example.com") {
		t.Errorf("list users = %d: %s", code, b)
	}
	// Promote to admin + change password.
	if code, _ := call(t, c, "PUT", ts.URL+"/api/users/"+id, `{"role":"admin","password":"newpassword123"}`); code != http.StatusOK {
		t.Errorf("update user = %d", code)
	}
	// Weak password on create → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/users", `{"email":"w@example.com","password":"short"}`); code != http.StatusBadRequest {
		t.Errorf("weak password = %d, want 400", code)
	}
	// Duplicate email → 409.
	if code, _ := call(t, c, "POST", ts.URL+"/api/users", create); code != http.StatusConflict {
		t.Errorf("duplicate user = %d, want 409", code)
	}
	// Delete the created (other) user → 200.
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/users/"+id, ""); code != http.StatusOK {
		t.Errorf("delete user = %d", code)
	}
	_ = st
}

func TestSelfDeleteRefused(t *testing.T) {
	ts, st, ctx := newTestAPI(t)
	admin := makeUser(t, st, ctx, "admin@example.com", store.RoleAdmin)
	makeUser(t, st, ctx, "admin2@example.com", store.RoleAdmin) // ensure not last admin concern
	c := loginClient(t, ts, "admin@example.com")
	if code, _ := call(t, c, "DELETE", ts.URL+"/api/users/"+admin.ID, ""); code != http.StatusBadRequest {
		t.Errorf("self-delete = %d, want 400", code)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	ts, _, c := adminAPI(t)
	if code, _ := call(t, c, "GET", ts.URL+"/api/settings", ""); code != http.StatusOK {
		t.Errorf("get settings = %d", code)
	}
	if code, _ := call(t, c, "PUT", ts.URL+"/api/settings", `{"acme.email":"ops@example.com","acme.staging":"true"}`); code != http.StatusOK {
		t.Errorf("set settings = %d", code)
	}
	if code, b := call(t, c, "GET", ts.URL+"/api/settings", ""); code != http.StatusOK || !strings.Contains(string(b), "ops@example.com") {
		t.Errorf("settings not persisted = %d: %s", code, b)
	}
}

func TestSnapshotsAndRollback(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Two mutations → at least two snapshots / versions.
	call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","enabled":true,"domains":["a.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`)
	call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","enabled":true,"domains":["b.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.2","port":80}],"tls":"none"}`)

	code, b := call(t, c, "GET", ts.URL+"/api/config/snapshots", "")
	if code != http.StatusOK {
		t.Fatalf("list snapshots = %d", code)
	}
	var snaps []struct {
		Version int64 `json:"version"`
		Current bool  `json:"current"`
	}
	if err := json.Unmarshal(b, &snaps); err != nil || len(snaps) < 2 {
		t.Fatalf("expected >=2 snapshots, got %s (%v)", b, err)
	}
	first := snaps[len(snaps)-1].Version // oldest

	if code, _ := call(t, c, "GET", ts.URL+"/api/config/snapshots/1", ""); code != http.StatusOK {
		t.Errorf("get snapshot v1 = %d", code)
	}
	// Roll back to the first version.
	if code, rb := call(t, c, "POST", ts.URL+"/api/config/rollback/"+itoa(first), ""); code != http.StatusOK {
		t.Errorf("rollback = %d: %s", code, rb)
	}
	// Invalid version in path → 400.
	if code, _ := call(t, c, "POST", ts.URL+"/api/config/rollback/abc", ""); code != http.StatusBadRequest {
		t.Errorf("rollback bad version = %d, want 400", code)
	}
	// Nonexistent version → 404.
	if code, _ := call(t, c, "POST", ts.URL+"/api/config/rollback/99999", ""); code != http.StatusNotFound {
		t.Errorf("rollback missing = %d, want 404", code)
	}
}

func TestConfigPreviewIsReadable(t *testing.T) {
	ts, _, c := adminAPI(t)
	call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","enabled":true,"domains":["p.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`)
	code, b := call(t, c, "GET", ts.URL+"/api/config/preview", "")
	if code != http.StatusOK {
		t.Fatalf("preview = %d", code)
	}
	if !strings.Contains(string(b), "p.example.com") || !strings.Contains(string(b), `"config"`) {
		t.Errorf("preview missing rendered host: %s", b)
	}
}

func TestReadOnlyEndpoints(t *testing.T) {
	ts, _, c := adminAPI(t)
	for _, path := range []string{"/api/listeners", "/api/traefik/status", "/api/traefik/logs", "/api/audit", "/api/notifications"} {
		if code, _ := call(t, c, "GET", ts.URL+path, ""); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
	}
}

func TestAuditTrailRecorded(t *testing.T) {
	ts, _, c := adminAPI(t)
	call(t, c, "POST", ts.URL+"/api/hosts", `{"kind":"proxy","enabled":true,"domains":["audit.example.com"],"upstreams":[{"scheme":"http","host":"10.0.0.1","port":80}],"tls":"none"}`)
	code, b := call(t, c, "GET", ts.URL+"/api/audit", "")
	if code != http.StatusOK || !strings.Contains(string(b), "host.create") {
		t.Errorf("audit trail missing host.create: %d %s", code, b)
	}
	if !strings.Contains(string(b), "admin@example.com") {
		t.Errorf("audit entry missing actor email: %s", b)
	}
}

func TestTraefikMetricsUnavailableWithoutProcess(t *testing.T) {
	ts, _, c := adminAPI(t)
	// No managed Traefik in tests → the read-only API proxy returns 503, not 500.
	if code, _ := call(t, c, "GET", ts.URL+"/api/traefik/overview", ""); code != http.StatusServiceUnavailable {
		t.Errorf("overview = %d, want 503", code)
	}
	if code, _ := call(t, c, "GET", ts.URL+"/api/import/docker", ""); code != http.StatusServiceUnavailable {
		t.Errorf("docker discover = %d, want 503", code)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}

// TestStrictDecodeRejectsUnknownFields verifies decodeJSONStrict is wired on the
// fixed-payload endpoints: the exact request shape succeeds, but an unknown/typo'd
// field is rejected with 400 instead of being silently dropped.
func TestStrictDecodeRejectsUnknownFields(t *testing.T) {
	ts, _, c := adminAPI(t)
	good := `{"email":"u@example.com","name":"U","password":"s3cret-pass","role":"viewer"}`
	if code, b := call(t, c, "POST", ts.URL+"/api/users", good); code != http.StatusCreated {
		t.Fatalf("valid create user = %d: %s", code, b)
	}
	bad := `{"email":"v@example.com","name":"V","password":"s3cret-pass","role":"viewer","bogus":1}`
	if code, _ := call(t, c, "POST", ts.URL+"/api/users", bad); code != http.StatusBadRequest {
		t.Errorf("unknown field on a strict endpoint should be 400, got %d", code)
	}
}

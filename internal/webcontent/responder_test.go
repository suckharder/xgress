package webcontent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/store"
)

func newResponder(t *testing.T) (*Responder, *store.Store, context.Context) {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir(), DBDriver: config.DriverSQLite}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(st), st, ctx
}

func serve(r *Responder, method, target string) *http.Response {
	mux := http.NewServeMux()
	r.Register(mux)
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Result()
}

// S5: served status/error-page HTML carries a strict CSP that neutralises scripts
// (and nosniff), so operator-supplied custom HTML can't become stored XSS.
func TestStatusPageStrictCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	writeStatusPage(rec, http.StatusNotFound, `<img src=x onerror=alert(1)><script>alert(2)</script>`)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("status page missing strict CSP, got %q", csp)
	}
	if strings.Contains(csp, "script-src") {
		t.Errorf("CSP must not grant a script-src (scripts fall back to default-src 'none'): %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("status page missing X-Content-Type-Options: nosniff")
	}
}

func TestBannedReturns403(t *testing.T) {
	r, _, _ := newResponder(t)
	resp := serve(r, "GET", BannedPath)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("banned status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "403") {
		t.Errorf("banned body missing 403: %q", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("banned content-type = %q", ct)
	}
}

func TestDefaultSiteModes(t *testing.T) {
	r, st, ctx := newResponder(t)

	// Default (no setting) → 404.
	if resp := serve(r, "GET", DefaultPath); resp.StatusCode != 404 {
		t.Errorf("default mode status = %d, want 404", resp.StatusCode)
	}

	// Welcome mode → 200 with the welcome page.
	_ = st.SetSetting(ctx, KeyDefaultMode, "welcome")
	resp := serve(r, "GET", DefaultPath)
	if resp.StatusCode != 200 {
		t.Errorf("welcome status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "It works") {
		t.Errorf("welcome body unexpected: %q", body)
	}

	// Custom mode → configured status + HTML.
	_ = st.SetSetting(ctx, KeyDefaultMode, "custom")
	_ = st.SetSetting(ctx, KeyDefaultStatus, "503")
	_ = st.SetSetting(ctx, KeyDefaultHTML, "<h1>maintenance</h1>")
	resp = serve(r, "GET", DefaultPath)
	if resp.StatusCode != 503 {
		t.Errorf("custom status = %d, want 503", resp.StatusCode)
	}
	body, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "maintenance") {
		t.Errorf("custom body = %q", body)
	}

	// Redirect mode with a target → 302.
	_ = st.SetSetting(ctx, KeyDefaultMode, "redirect")
	_ = st.SetSetting(ctx, KeyDefaultRedirectTo, "https://example.com")
	resp = serve(r, "GET", DefaultPath)
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://example.com" {
		t.Errorf("redirect Location = %q", loc)
	}

	// Redirect mode with no target falls back to 404.
	_ = st.SetSetting(ctx, KeyDefaultRedirectTo, "")
	if resp := serve(r, "GET", DefaultPath); resp.StatusCode != 404 {
		t.Errorf("redirect w/o target status = %d, want 404", resp.StatusCode)
	}
}

func TestErrorPageMatching(t *testing.T) {
	r, st, ctx := newResponder(t)
	h := &store.Host{
		Kind:    store.HostKindProxy,
		Domains: []string{"x.example.com"},
		TLS:     store.TLSNone,
		ErrorPages: []store.ErrorPage{
			{Status: "404", HTML: "<h1>not here</h1>"},
			{Status: "500-599", HTML: "<h1>our fault</h1>"},
		},
	}
	if err := st.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	// Exact match.
	resp := serve(r, "GET", ErrorPath+h.ID+"/404")
	if resp.StatusCode != 404 {
		t.Errorf("error 404 status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "not here") {
		t.Errorf("404 page = %q", body)
	}

	// Range match (502 ∈ 500-599).
	resp = serve(r, "GET", ErrorPath+h.ID+"/502")
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 502 || !strings.Contains(string(body), "our fault") {
		t.Errorf("range error page: status=%d body=%q", resp.StatusCode, body)
	}

	// No matching custom page → default status page (still correct status).
	resp = serve(r, "GET", ErrorPath+h.ID+"/418")
	if resp.StatusCode != 418 {
		t.Errorf("unmatched status = %d, want 418", resp.StatusCode)
	}

	// Unknown host → default status page, no panic.
	resp = serve(r, "GET", ErrorPath+"nonexistent/500")
	if resp.StatusCode != 500 {
		t.Errorf("unknown host error status = %d, want 500", resp.StatusCode)
	}
}

func TestStatusMatches(t *testing.T) {
	cases := []struct {
		spec string
		code int
		want bool
	}{
		{"404", 404, true},
		{"404", 500, false},
		{"500,502", 502, true},
		{"500,502", 503, false},
		{"500-599", 502, true},
		{"500-599", 499, false},
		{"500-599", 600, false},
		{" 404 , 500-599 ", 550, true},
		{"abc", 500, false},
	}
	for _, c := range cases {
		if got := statusMatches(c.spec, c.code); got != c.want {
			t.Errorf("statusMatches(%q, %d) = %v, want %v", c.spec, c.code, got, c.want)
		}
	}
}

func TestErrorPathMalformed(t *testing.T) {
	r, _, _ := newResponder(t)
	// Missing the status segment.
	resp := serve(r, "GET", ErrorPath+"justhostid")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("malformed error path = %d, want 404", resp.StatusCode)
	}
}

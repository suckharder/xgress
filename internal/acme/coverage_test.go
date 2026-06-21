package acme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
)

// These are pure unit tests (no CA, no Docker, no network): they cover the parts
// of the acme package that don't require a live ACME server — the DNS-provider
// plumbing, the HTTP-01 responder, and the parse/marshal helpers. The live
// issuance path (Obtain/getOrCreateAccount) is covered by the e2e ACME tier.

func testStoreBox(t *testing.T) (*store.Store, *secrets.Box) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), &config.Config{DataDir: dir, DBDriver: config.DriverSQLite})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := secrets.Load(dir + "/secret.key")
	if err != nil {
		t.Fatalf("secrets.Load: %v", err)
	}
	return st, box
}

func TestDNSProviderCatalog(t *testing.T) {
	cat := DNSProviderCatalog()
	if len(cat) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, p := range cat {
		if p.Code == "" || p.Label == "" {
			t.Errorf("provider missing code/label: %+v", p)
		}
		if seen[p.Code] {
			t.Errorf("duplicate provider code %q", p.Code)
		}
		seen[p.Code] = true
		for _, f := range p.Fields {
			if f.Key == "" || f.Label == "" {
				t.Errorf("provider %q has a malformed field: %+v", p.Code, f)
			}
		}
	}
	// Spot-check a provider we wire elsewhere in tests.
	if !seen["cloudflare"] {
		t.Error("expected cloudflare in the DNS catalog")
	}
}

func TestSetEnvRestores(t *testing.T) {
	const k = "XGRESS_ACME_SETENV_PROBE"

	// Key absent → set → restore must unset it again.
	_ = os.Unsetenv(k)
	restore := setEnv(map[string]string{k: "v1"})
	if os.Getenv(k) != "v1" {
		t.Fatalf("setEnv did not apply: %q", os.Getenv(k))
	}
	restore()
	if _, ok := os.LookupEnv(k); ok {
		t.Error("restore should have unset a previously-absent key")
	}

	// Key present → set → restore must put the original value back.
	t.Setenv(k, "original")
	restore2 := setEnv(map[string]string{k: "override"})
	if os.Getenv(k) != "override" {
		t.Fatalf("setEnv did not override: %q", os.Getenv(k))
	}
	restore2()
	if os.Getenv(k) != "original" {
		t.Errorf("restore should have put back %q, got %q", "original", os.Getenv(k))
	}
}

func TestDNSProviderBuildAndErrors(t *testing.T) {
	st, box := testStoreBox(t)
	m := New(Options{Store: st, Box: box})
	ctx := context.Background()

	// Happy path: a cloudflare provider builds from a stored token without network.
	enc, err := box.EncryptString(`{"CF_DNS_API_TOKEN":"dummy-token"}`)
	if err != nil {
		t.Fatal(err)
	}
	rec := &store.DNSProvider{Name: "cf", Provider: "cloudflare", ConfigEnc: enc}
	if err := st.CreateDNSProvider(ctx, rec); err != nil {
		t.Fatal(err)
	}
	p, cleanup, err := m.dnsProvider(ctx, rec.ID)
	if err != nil {
		t.Fatalf("dnsProvider (happy): %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
	cleanup() // releases envMu + restores env

	// Unknown id → store error.
	if _, _, err := m.dnsProvider(ctx, "does-not-exist"); err == nil {
		t.Error("expected error for unknown DNS provider id")
	}

	// Undecryptable config → decrypt error.
	bad := &store.DNSProvider{Name: "bad", Provider: "cloudflare", ConfigEnc: "not-real-ciphertext"}
	if err := st.CreateDNSProvider(ctx, bad); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.dnsProvider(ctx, bad.ID); err == nil {
		t.Error("expected decrypt error for corrupt config")
	}

	// Unknown lego provider code → factory error (after a successful decrypt).
	enc2, _ := box.EncryptString(`{"X":"y"}`)
	unk := &store.DNSProvider{Name: "unk", Provider: "not-a-real-provider", ConfigEnc: enc2}
	if err := st.CreateDNSProvider(ctx, unk); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.dnsProvider(ctx, unk.ID); err == nil {
		t.Error("expected error for unknown lego provider code")
	}
}

func TestHTTP01ResponderServeHTTP(t *testing.T) {
	r := NewHTTP01Responder()
	r.Present("example.test", "tok-123", "keyauth-value")

	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec.Code, rec.Body.String()
	}

	// Correct token → 200 + keyAuth.
	if code, body := get("/.well-known/acme-challenge/tok-123"); code != http.StatusOK || body != "keyauth-value" {
		t.Errorf("valid token: code=%d body=%q", code, body)
	}
	// Unknown token → 404.
	if code, _ := get("/.well-known/acme-challenge/unknown"); code != http.StatusNotFound {
		t.Errorf("unknown token: code=%d, want 404", code)
	}
	// Wrong path prefix → 404.
	if code, _ := get("/not-a-challenge"); code != http.StatusNotFound {
		t.Errorf("wrong prefix: code=%d, want 404", code)
	}
	// After CleanUp the token is gone → 404.
	r.CleanUp("example.test", "tok-123", "keyauth-value")
	if code, _ := get("/.well-known/acme-challenge/tok-123"); code != http.StatusNotFound {
		t.Errorf("after cleanup: code=%d, want 404", code)
	}
}

func TestLeafExpiryErrors(t *testing.T) {
	if _, err := leafExpiry([]byte("not a pem block")); err == nil {
		t.Error("expected error for non-PEM input")
	}
	// Valid PEM framing but garbage DER → x509 parse error.
	badDER := []byte("-----BEGIN CERTIFICATE-----\nYm9ndXM=\n-----END CERTIFICATE-----\n")
	if _, err := leafExpiry(badDER); err == nil {
		t.Error("expected error for invalid certificate DER")
	}
}

func TestUnmarshalHelpersRejectGarbage(t *testing.T) {
	if _, err := unmarshalKey("not a pem key"); err == nil {
		t.Error("unmarshalKey should reject non-PEM input")
	}
	if _, err := unmarshalRegistration("{not json"); err == nil {
		t.Error("unmarshalRegistration should reject invalid JSON")
	}
}

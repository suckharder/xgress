package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/config"
)

// TestSessionCookieSecureMatrix locks down the Secure attribute of the admin
// session cookie across Dev / AdminInsecureCookie: it must be Secure in
// production, and dropped only when explicitly opted out (so the admin UI can
// authenticate over plain HTTP on a trusted network).
func TestSessionCookieSecureMatrix(t *testing.T) {
	cases := []struct {
		dev, insecure, wantSecure bool
	}{
		{dev: false, insecure: false, wantSecure: true}, // production
		{dev: true, insecure: false, wantSecure: false}, // dev mode
		{dev: false, insecure: true, wantSecure: false}, // explicit insecure-cookie opt-in
		{dev: true, insecure: true, wantSecure: false},  // both
	}
	for _, c := range cases {
		s := &Server{cfg: &config.Config{Dev: c.dev, AdminInsecureCookie: c.insecure}}

		set := httptest.NewRecorder()
		s.setSessionCookie(set, "token", time.Now().Add(time.Hour))
		clear := httptest.NewRecorder()
		s.clearSessionCookie(clear)

		for _, rec := range []*httptest.ResponseRecorder{set, clear} {
			ck := findCookie(rec.Result().Cookies(), sessionCookie)
			if ck == nil {
				t.Fatalf("dev=%v insecure=%v: no %q cookie set", c.dev, c.insecure, sessionCookie)
			}
			if ck.Secure != c.wantSecure {
				t.Errorf("dev=%v insecure=%v: cookie Secure=%v, want %v", c.dev, c.insecure, ck.Secure, c.wantSecure)
			}
			if !ck.HttpOnly {
				t.Errorf("dev=%v insecure=%v: session cookie must always be HttpOnly", c.dev, c.insecure)
			}
		}
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

package notify

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newUnguarded builds a dispatcher with the dial-time SSRF guard disabled, so a test
// can point a webhook at a loopback httptest server. The guard correctly blocks
// loopback in production — that behaviour is verified in TestWebhookDialGuardBlocksLoopback.
func newUnguarded(provider ConfigProvider) *Dispatcher {
	d := New(provider, discardLog())
	d.dialer.Control = nil // Control is read per-dial, so this disables the guard
	return d
}

func TestConfigEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"empty", Config{}, false},
		{"webhook only", Config{WebhookURL: "http://x"}, true},
		{"email needs host", Config{EmailTo: "a@b.c"}, false},
		{"email + host", Config{EmailTo: "a@b.c", SMTPHost: "smtp"}, true},
	}
	for _, c := range cases {
		if got := c.cfg.Enabled(); got != c.want {
			t.Errorf("%s: Enabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNotifyPostsToWebhook(t *testing.T) {
	var got atomic.Pointer[map[string]any]
	var calls int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		if r.Method != http.MethodPost {
			t.Errorf("webhook method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		var m map[string]any
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &m); err != nil {
			t.Errorf("payload not JSON: %v", err)
		}
		got.Store(&m)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	d := newUnguarded(func(ctx context.Context) Config { return Config{WebhookURL: ts.URL} })
	d.Notify(context.Background(), "error", "Cert failed", "details here")

	if atomic.LoadInt64(&calls) != 1 {
		t.Fatalf("webhook called %d times, want 1", atomic.LoadInt64(&calls))
	}
	m := *got.Load()
	if m["level"] != "error" || m["subject"] != "Cert failed" || m["body"] != "details here" {
		t.Errorf("payload mismatch: %v", m)
	}
	if m["source"] != "xgress" {
		t.Errorf("source = %v", m["source"])
	}
}

func TestNotifyNoChannelIsNoop(t *testing.T) {
	var calls int64
	d := New(func(ctx context.Context) Config { return Config{} }, discardLog())
	// Must not panic or attempt delivery when nothing is configured.
	d.Notify(context.Background(), "info", "s", "b")
	if atomic.LoadInt64(&calls) != 0 {
		t.Fatal("delivery attempted with no channel configured")
	}
}

func TestTestWebhookSurfacesErrors(t *testing.T) {
	// No channel → explicit error.
	d := newUnguarded(func(ctx context.Context) Config { return Config{} })
	if err := d.Test(context.Background(), Config{}); err == nil {
		t.Error("Test with no channel should error")
	}

	// Webhook returning 500 → error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := d.Test(context.Background(), Config{WebhookURL: bad.URL}); err == nil {
		t.Error("Test against a 5xx webhook should error")
	}

	// Webhook returning 200 → success.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer ok.Close()
	if err := d.Test(context.Background(), Config{WebhookURL: ok.URL}); err != nil {
		t.Errorf("Test against a 2xx webhook should succeed: %v", err)
	}
}

// S6: the dial-time SSRF guard must block a webhook pointed at loopback (e.g.
// xgress's own provider/admin) even if it passed a save-time check (DNS rebinding).
func TestWebhookDialGuardBlocksLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()

	d := New(func(ctx context.Context) Config { return Config{WebhookURL: ts.URL} }, discardLog()) // guard ON
	err := d.Test(context.Background(), Config{WebhookURL: ts.URL})                                // ts.URL is 127.0.0.1:port
	if err == nil {
		t.Fatal("a loopback webhook must be blocked by the dial-time SSRF guard")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should come from the SSRF guard, got: %v", err)
	}
}

func TestBuildMessageHeaders(t *testing.T) {
	msg := string(buildMessage("from@x.com", "to@y.com", "Hi", "Body text"))
	for _, want := range []string{"From: from@x.com", "To: to@y.com", "Subject: Hi", "Content-Type: text/plain; charset=utf-8", "Body text"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	// Headers must be separated from the body by a blank line.
	if !strings.Contains(msg, "\r\n\r\nBody text") {
		t.Error("message body not separated by blank line")
	}
}

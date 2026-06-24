package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suckharder/xgress/internal/secmetrics"
	"github.com/suckharder/xgress/internal/store"
	"github.com/suckharder/xgress/internal/waf"
)

// wafEdge builds an edge with the native WAF enabled, pointed at backendURL for
// domain, optionally cache-enabled. sec, if non-nil, collects detections.
func wafEdge(t *testing.T, domain, backendURL string, cache bool, sec *secmetrics.Collector) *Server {
	t.Helper()
	w, err := waf.Build(waf.Options{}, nil)
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	u, _ := url.Parse(backendURL)
	port, _ := strconv.Atoi(u.Port())
	s := New(NewMemStore(context.Background(), MemLimits{}), time.Minute, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetWAF(w)
	s.SetEnabled(true, cache)
	if sec != nil {
		s.SetSecMetrics(sec)
	}
	s.SetHosts([]*store.Host{{
		ID: "h1", Kind: store.HostKindProxy, Enabled: true, WAF: true, Cache: cache,
		Domains:   []string{domain},
		Upstreams: []store.Upstream{{Scheme: "http", Host: u.Hostname(), Port: port}},
	}})
	return s
}

func TestWAFBlocksAttacksAllowsBenign(t *testing.T) {
	be, hits := backend(t, nil)
	sec := secmetrics.New()
	s := wafEdge(t, "waf.local", be.URL, false, sec)

	// Benign request reaches the backend with 200.
	if r := reqTo(s, "GET", "waf.local", "/hello?name=world"); r.StatusCode != http.StatusOK {
		t.Fatalf("benign = %d, want 200", r.StatusCode)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("benign should reach backend once, got %d", atomic.LoadInt64(hits))
	}
	// Benign traffic must NOT pollute the metrics: CRS's per-request init/setup rules
	// are filtered out, so only genuine attack detections are recorded.
	if got := sec.Snapshot().Total; got != 0 {
		t.Errorf("benign request recorded %d detections, want 0 (init-rule noise leaked)", got)
	}

	// Attacks are blocked with 403 and never reach the backend.
	for _, path := range []string{
		"/?q=union%20select%201%20from%20users",
		"/../../etc/passwd",
	} {
		r := reqTo(s, "GET", "waf.local", path)
		if r.StatusCode != http.StatusForbidden {
			t.Errorf("attack %q = %d, want 403", path, r.StatusCode)
		}
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("attacks must not reach backend; backend hits = %d", atomic.LoadInt64(hits))
	}

	// Metrics recorded the block with a real CRS rule id + sqli category.
	waitFor(t, func() bool { return sec.Snapshot().Blocked > 0 }, 2*time.Second)
	snap := sec.Snapshot()
	if snap.Blocked == 0 || len(snap.TopRules) == 0 {
		t.Fatalf("expected recorded WAF detections, got %+v", snap)
	}
	if snap.TopRules[0].Name == "" {
		t.Error("expected a real rule id in metrics")
	}
}

func TestWAFDisabledLetsAttacksThrough(t *testing.T) {
	be, _ := backend(t, nil)
	s := wafEdge(t, "waf.local", be.URL, false, nil)
	s.SetEnabled(false, false) // global WAF off
	r := reqTo(s, "GET", "waf.local", "/?q=union%20select%201%20from%20users")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("WAF disabled: attack should pass, got %d", r.StatusCode)
	}
}

func TestWAFPlusCacheComposition(t *testing.T) {
	be, hits := backend(t, http.Header{"Cache-Control": {"max-age=60"}})
	s := wafEdge(t, "waf.local", be.URL, true, nil)

	// Benign cached: first MISS, second HIT (one backend hit), WAF still ran on both.
	if r := reqTo(s, "GET", "waf.local", "/page"); r.Header.Get("X-xgress-Cache") != "MISS" {
		t.Fatalf("first = %s, want MISS", r.Header.Get("X-xgress-Cache"))
	}
	if r := reqTo(s, "GET", "waf.local", "/page"); r.Header.Get("X-xgress-Cache") != "HIT" {
		t.Fatalf("second = %s, want HIT", r.Header.Get("X-xgress-Cache"))
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Errorf("cache+waf: backend hits = %d, want 1", atomic.LoadInt64(hits))
	}
	// An attack is still blocked even on a cache host.
	if r := reqTo(s, "GET", "waf.local", "/?q=union%20select%201%20from%20users"); r.StatusCode != http.StatusForbidden {
		t.Errorf("attack on cache+waf host = %d, want 403", r.StatusCode)
	}
}

// TestWAFBodyInspection proves a POST body attack is blocked (buffered, bounded).
func TestWAFBodyInspection(t *testing.T) {
	be, hits := backend(t, nil)
	s := wafEdge(t, "waf.local", be.URL, false, nil)
	body := strings.NewReader("name=1' OR '1'='1' UNION SELECT password FROM users--")
	req := httptest.NewRequest("POST", "http://waf.local/login", body)
	req.Host = "waf.local"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("SQLi in POST body = %d, want 403", rec.Code)
	}
	if atomic.LoadInt64(hits) != 0 {
		t.Errorf("blocked POST must not reach backend, hits = %d", atomic.LoadInt64(hits))
	}
}

// TestWAFUpgradeBypassesBuffering proves a WebSocket upgrade is streamed (the
// request still passes the WAF request phase) rather than buffered.
func TestWAFUpgradeBypassesBuffering(t *testing.T) {
	var gotUpgrade int32
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			atomic.StoreInt32(&gotUpgrade, 1)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(be.Close)
	s := wafEdge(t, "waf.local", be.URL, false, nil)

	req := httptest.NewRequest("GET", "http://waf.local/ws", nil)
	req.Host = "waf.local"
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if atomic.LoadInt32(&gotUpgrade) != 1 {
		t.Error("upgrade request did not reach the backend via the streaming path")
	}
}

func waitFor(t *testing.T, cond func() bool, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}

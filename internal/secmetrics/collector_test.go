package secmetrics

import (
	"fmt"
	"testing"
	"time"
)

func TestCapCounts(t *testing.T) {
	m := map[string]int{"heavy": 999}
	for i := 0; i < 100; i++ {
		m[fmt.Sprintf("k%d", i)] = 1
	}
	capCounts(m, 50, 30) // over the cap → evict to 30 highest-count keys
	if len(m) != 30 {
		t.Fatalf("len = %d, want 30 after eviction", len(m))
	}
	if m["heavy"] != 999 {
		t.Fatal("highest-count key was evicted")
	}
	capCounts(m, 1000, 500) // under the cap → no-op
	if len(m) != 30 {
		t.Fatalf("capCounts evicted while under cap: len = %d", len(m))
	}
}

func TestCapOldestHours(t *testing.T) {
	m := map[int64]int{}
	for h := int64(0); h < 100; h++ {
		m[h] = 1
	}
	capOldestHours(m, 10)
	if len(m) != 10 {
		t.Fatalf("len = %d, want 10", len(m))
	}
	if _, ok := m[99]; !ok {
		t.Fatal("newest bucket evicted")
	}
	if _, ok := m[0]; ok {
		t.Fatal("oldest bucket kept")
	}
}

// TestCollectorBoundsFlood proves the wiring: a flood of distinct client IPs keeps
// byIP bounded while the heavy-hitter (high-count) IP survives eviction.
func TestCollectorBoundsFlood(t *testing.T) {
	c := New()
	for i := 0; i < 200; i++ { // a heavy hitter
		c.add(Event{ClientIP: "9.9.9.9", At: time.Now()})
	}
	for i := 0; i < maxCountKeys+5000; i++ { // flood past the cap with singletons
		c.add(Event{ClientIP: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), At: time.Now()})
	}
	c.mu.Lock()
	n, heavyKept := len(c.byIP), c.byIP["9.9.9.9"]
	c.mu.Unlock()
	if n > maxCountKeys {
		t.Fatalf("byIP not bounded: %d > %d", n, maxCountKeys)
	}
	if heavyKept != 200 {
		t.Fatalf("heavy-hitter IP evicted (count=%d)", heavyKept)
	}
}

func TestRecordAggregates(t *testing.T) {
	c := New()
	// A native WAF detection for an SQLi block (as the edge would build it).
	c.Record(Event{
		ClientIP: "203.0.113.7", Host: "app.example.com", Method: "GET", URI: "/?q=1 OR 1=1",
		RuleID: "942100", Message: "SQL Injection Attack Detected",
		Category: Category([]string{"attack-sqli", "OWASP_CRS"}, "SQL Injection"), Severity: 2, Blocked: true,
	})
	s := c.Snapshot()
	if s.Total != 1 || s.Blocked != 1 {
		t.Fatalf("expected 1 total/blocked, got %d/%d", s.Total, s.Blocked)
	}
	if len(s.TopRules) != 1 || s.TopRules[0].Name != "942100" || s.TopRules[0].Label == "" {
		t.Errorf("unexpected top rule: %+v", s.TopRules)
	}
	if len(s.Categories) != 1 || s.Categories[0].Name != "sqli" {
		t.Errorf("expected sqli category, got %+v", s.Categories)
	}
	if len(s.TopIPs) != 1 || s.TopIPs[0].Name != "203.0.113.7" {
		t.Errorf("expected top IP, got %+v", s.TopIPs)
	}
	if len(s.TopHosts) != 1 || s.TopHosts[0].Name != "app.example.com" {
		t.Errorf("expected top host, got %+v", s.TopHosts)
	}
	if len(s.Recent) != 1 || s.Recent[0].URI != "/?q=1 OR 1=1" {
		t.Errorf("expected recent event, got %+v", s.Recent)
	}
	if len(s.Series) != 24 {
		t.Errorf("expected 24-point series, got %d", len(s.Series))
	}
}

func TestRecordDerivesCategory(t *testing.T) {
	c := New()
	// No explicit category → derived from the message text.
	c.Record(Event{ClientIP: "198.51.100.4", RuleID: "941100", Message: "XSS Attack Detected", Blocked: true})
	s := c.Snapshot()
	if s.Total != 1 {
		t.Fatalf("expected 1 event, got %d", s.Total)
	}
	if s.TopRules[0].Name != "941100" || s.Categories[0].Name != "xss" || s.TopIPs[0].Name != "198.51.100.4" {
		t.Errorf("unexpected: rule=%v cat=%v ip=%v", s.TopRules, s.Categories, s.TopIPs)
	}
}

func TestObserverDeliveredViaWorker(t *testing.T) {
	c := New()
	got := make(chan Event, 4)
	c.AddObserver(func(e Event) { got <- e })
	c.Record(Event{ClientIP: "1.2.3.4", RuleID: "942100", Message: "SQLi", Blocked: true})
	select {
	case e := <-got:
		if e.ClientIP != "1.2.3.4" || e.RuleID != "942100" {
			t.Errorf("observer got %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("observer not invoked — single worker not delivering events")
	}
}

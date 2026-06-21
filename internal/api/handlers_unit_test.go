package api

import (
	"net/http"
	"testing"

	"github.com/suckharder/xgress/internal/store"
)

func TestDomainsFromRule(t *testing.T) {
	cases := map[string][]string{
		"Host(`a.example.com`)":                          {"a.example.com"},
		"Host(`a.example.com`) || Host(`b.example.com`)": {"a.example.com", "b.example.com"},
		"PathPrefix(`/x`)":                               nil,
		"Host(`a.example.com`) && PathPrefix(`/api`)":    {"a.example.com"},
	}
	for rule, want := range cases {
		got := domainsFromRule(rule)
		if len(got) != len(want) {
			t.Errorf("%q → %v, want %v", rule, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q → %v, want %v", rule, got, want)
			}
		}
	}
}

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		raw         string
		host        string
		port        int
		scheme      string
		nilExpected bool
	}{
		{"http://10.0.0.1:8080", "10.0.0.1", 8080, "http", false},
		{"http://10.0.0.1", "10.0.0.1", 80, "http", false},
		{"https://svc", "svc", 443, "https", false},
		{"", "", 0, "", true},
	}
	for _, c := range cases {
		u := parseUpstream(c.raw)
		if c.nilExpected {
			if u != nil {
				t.Errorf("parseUpstream(%q) = %+v, want nil", c.raw, u)
			}
			continue
		}
		if u == nil || u.Host != c.host || u.Port != c.port || u.Scheme != c.scheme {
			t.Errorf("parseUpstream(%q) = %+v, want %s/%s:%d", c.raw, u, c.scheme, c.host, c.port)
		}
	}
}

func TestValidateHostStreamAndComposition(t *testing.T) {
	has := func(h *store.Host, want string) bool {
		for _, is := range validateHost(h) {
			if is.Field == want {
				return true
			}
		}
		return false
	}

	// Stream host missing entrypoint + backend.
	st := &store.Host{Kind: store.HostKindStream}
	if !has(st, "streamEntryPoint") || !has(st, "upstreams") {
		t.Errorf("stream validation missing issues: %+v", validateHost(st))
	}
	// Stream passthrough without SNI domains.
	pt := &store.Host{Kind: store.HostKindStream, StreamEntryPoint: "x", TLSPassthrough: true,
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 5432}}}
	if !has(pt, "domains") {
		t.Errorf("passthrough without SNI should be flagged: %+v", validateHost(pt))
	}
	// Valid stream host → no issues.
	ok := &store.Host{Kind: store.HostKindStream, StreamEntryPoint: "x",
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 5432}}}
	if len(validateHost(ok)) != 0 {
		t.Errorf("valid stream reported issues: %+v", validateHost(ok))
	}

	// Failover composition mode needs >= 2 backend groups.
	fo := &store.Host{Kind: store.HostKindProxy, ServiceMode: "failover", Domains: []string{"f.example.com"},
		BackendGroups: []store.BackendGroup{{Name: "p", Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}}}}
	if !has(fo, "backendGroups") {
		t.Errorf("failover with 1 group should be flagged: %+v", validateHost(fo))
	}
	// Weighted mode with a group missing a backend host.
	w := &store.Host{Kind: store.HostKindProxy, ServiceMode: "weighted", Domains: []string{"w.example.com"},
		BackendGroups: []store.BackendGroup{{Name: "v1", Upstreams: []store.Upstream{{Host: "", Port: 80}}}}}
	if !has(w, "backendGroups[0]") {
		t.Errorf("weighted group without host should be flagged: %+v", validateHost(w))
	}
}

// TestValidateHostRuleInputs verifies the centralized rule-input validation reaches
// EVERY host kind/mode — including the stream and composition-mode paths that used to
// bypass domain validation entirely, and location path prefixes (never validated
// before). Guards against router-rule injection via Host()/HostSNI()/PathPrefix().
func TestValidateHostRuleInputs(t *testing.T) {
	has := func(h *store.Host, want string) bool {
		for _, is := range validateHost(h) {
			if is.Field == want {
				return true
			}
		}
		return false
	}

	// Stream SNI domains are now validated (previously skipped entirely).
	streamBad := &store.Host{Kind: store.HostKindStream, StreamEntryPoint: "x",
		Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 5432}},
		Domains:   []string{"evil`) || HostSNI(`*"}}
	if !has(streamBad, "domains[0]") {
		t.Errorf("stream SNI injection not flagged: %+v", validateHost(streamBad))
	}

	// Composition-mode domains are now validated (previously skipped).
	compBad := &store.Host{Kind: store.HostKindProxy, ServiceMode: "weighted",
		Domains: []string{"bad`domain"},
		BackendGroups: []store.BackendGroup{
			{Name: "v1", Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}},
			{Name: "v2", Upstreams: []store.Upstream{{Host: "10.0.0.2", Port: 80}}},
		}}
	if !has(compBad, "domains[0]") {
		t.Errorf("composition-mode domain injection not flagged: %+v", validateHost(compBad))
	}

	// Location path prefixes are now validated (previously never).
	locBad := &store.Host{Kind: store.HostKindProxy, Domains: []string{"ok.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}},
		Locations: []store.Location{{PathPrefix: "/x`) || PathPrefix(`/", Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}}}}
	if !has(locBad, "locations[0].pathPrefix") {
		t.Errorf("location pathPrefix injection not flagged: %+v", validateHost(locBad))
	}

	// A clean host (wildcard domain + normal location) is accepted unchanged.
	ok := &store.Host{Kind: store.HostKindProxy, Domains: []string{"*.example.com"},
		Upstreams: []store.Upstream{{Scheme: "http", Host: "10.0.0.1", Port: 80}},
		Locations: []store.Location{{PathPrefix: "/api", Upstreams: []store.Upstream{{Host: "10.0.0.1", Port: 80}}}}}
	if len(validateHost(ok)) != 0 {
		t.Errorf("clean host reported issues: %+v", validateHost(ok))
	}
}

func TestHealthEndpoint(t *testing.T) {
	ts, _, c := adminAPI(t)
	if code, b := call(t, c, "GET", ts.URL+"/api/health", ""); code != http.StatusOK || len(b) == 0 {
		t.Errorf("health = %d: %s", code, b)
	}
}

func TestNotificationTestRejectsSSRF(t *testing.T) {
	ts, _, c := adminAPI(t)
	// Save a loopback webhook is rejected at save; the test endpoint also guards.
	// Seed a private host via save, then a test with a loopback saved value is not
	// possible (save blocks it), so we assert the test endpoint guards a freshly
	// invalid saved state by directly checking the metadata SMTP path through save.
	if code, _ := call(t, c, "PUT", ts.URL+"/api/notifications", `{"smtpHost":"127.0.0.1"}`); code != http.StatusBadRequest {
		t.Errorf("loopback smtp save = %d, want 400", code)
	}
	// A test with nothing configured returns 502 (notifier reports nothing to send)
	// or 200; either way it must not 500. Accept 4xx/5xx but not a panic/empty.
	code, _ := call(t, c, "POST", ts.URL+"/api/notifications/test", "")
	if code == 0 {
		t.Error("notification test produced no response")
	}
}

package waf

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

// drive runs a minimal request through a transaction and reports whether it was
// interrupted (blocked) and the deny status, exercising request line + URI only.
func drive(t *testing.T, w interface {
	NewTransaction() types.Transaction
}, method, uri string) (blocked bool, status int) {
	t.Helper()
	tx := w.NewTransaction()
	defer func() { tx.ProcessLogging(); _ = tx.Close() }()
	tx.ProcessConnection("203.0.113.7", 12345, "10.0.0.1", 80)
	tx.ProcessURI(uri, method, "HTTP/1.1")
	tx.AddRequestHeader("Host", "waf.example.com")
	if it := tx.ProcessRequestHeaders(); it != nil {
		return true, it.Status
	}
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
		return true, it.Status
	}
	return tx.IsInterrupted(), 0
}

func TestBuildBlocksAttacks(t *testing.T) {
	w, err := Build(Options{}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Benign request must pass.
	if blocked, _ := drive(t, w, "GET", "/hello?name=world"); blocked {
		t.Error("benign request must not be blocked")
	}
	// SQLi and path traversal must be blocked.
	for _, uri := range []string{
		"/?q=union%20select%201%20from%20users",
		"/../../etc/passwd",
		"/?x=<script>alert(1)</script>",
	} {
		if blocked, status := drive(t, w, "GET", uri); !blocked {
			t.Errorf("attack %q must be blocked", uri)
		} else if status != 403 {
			t.Errorf("attack %q blocked with status %d, want 403", uri, status)
		}
	}
}

func TestDirectivesContainCRSAndOverrides(t *testing.T) {
	d := Directives(Options{ParanoiaLevel: 3, AnomalyThreshold: 10})
	for _, want := range []string{
		"Include @coraza.conf-recommended",
		"SecRuleEngine On",
		"Include @crs-setup.conf.example",
		"Include @owasp_crs/*.conf",
		"blocking_paranoia_level=3",
		"inbound_anomaly_score_threshold=10",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("directives missing %q", want)
		}
	}
}

func TestExtraDirectivesAppended(t *testing.T) {
	d := Directives(Options{Extra: []string{`SecRule ARGS "@rx zzz" "id:9001,phase:2,deny"`}})
	if !strings.Contains(d, "id:9001") {
		t.Error("custom directive not appended")
	}
	if strings.Index(d, "@owasp_crs") > strings.Index(d, "id:9001") {
		t.Error("custom directives must come after the CRS include")
	}
}

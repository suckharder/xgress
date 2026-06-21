package traefikcfg

import (
	"strings"
	"testing"
)

func TestValidDomain(t *testing.T) {
	good := []string{
		"example.com",
		"sub.example.com",
		"*.example.com",     // wildcard cert
		"a-b_c.example.com", // hyphen + underscore
		"localhost",         // single label
		"xn--mnchen-3ya.de", // punycode
		"münchen.de",        // IDN / Unicode letters (lenient)
		"例え.テスト",            // non-Latin IDN
		"123.example.com",   // leading digits
	}
	for _, d := range good {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}

	bad := []string{
		"",                              // empty
		"   ",                           // whitespace only
		"ex ample.com",                  // space
		"a/b",                           // slash
		"a`b",                           // backtick (the injection char)
		"evil`) || ClientIP(`0.0.0.0/0", // full injection payload
		"a(b)",                          // parens
		"a|b",                           // pipe
		"a&b",                           // ampersand
		"a,b",                           // comma
		"a\"b",                          // quote
		"a\\b",                          // backslash
		"a\tb",                          // tab
	}
	for _, d := range bad {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

func TestValidPathPrefix(t *testing.T) {
	good := []string{"/", "/api", "/api/v1/users", "/a-b_c", "/foo(bar)", "/a%20b", "/.well-known/x"}
	for _, p := range good {
		if !validPathPrefix(p) {
			t.Errorf("validPathPrefix(%q) = false, want true", p)
		}
	}
	bad := []string{
		"api",                   // no leading slash
		"",                      // empty
		"/a`b",                  // backtick
		"/x`) || PathPrefix(`/", // injection payload
		"/a b",                  // space
		"/a\tb",                 // tab
		"/a\nb",                 // newline
	}
	for _, p := range bad {
		if validPathPrefix(p) {
			t.Errorf("validPathPrefix(%q) = true, want false", p)
		}
	}
}

func TestValidateRuleInputs(t *testing.T) {
	// Clean inputs → no issues (incl. empty entries, which are skipped here and
	// caught by the per-kind "at least one domain" checks elsewhere).
	if got := ValidateRuleInputs([]string{"a.example.com", "*.example.com", ""}, []string{"/api", ""}); len(got) != 0 {
		t.Errorf("clean inputs produced issues: %v", got)
	}
	// A bad domain and a bad path are each flagged with their indexed field.
	issues := ValidateRuleInputs([]string{"ok.com", "bad`domain"}, []string{"/ok", "bad-no-slash"})
	if !hasField(issues, "domains[1]") {
		t.Errorf("expected domains[1] issue, got %v", issues)
	}
	if !hasField(issues, "locations[1].pathPrefix") {
		t.Errorf("expected locations[1].pathPrefix issue, got %v", issues)
	}
}

func TestParseAllowIPs(t *testing.T) {
	valid, invalid := ParseAllowIPs([]string{
		"10.0.0.0/8", " 192.168.1.1 ", "::1", "2001:db8::/32", "", "   ", // valid (+ dropped blanks)
		"notanip", "10.0.0.0/99", "1.2.3.4`", "999.1.1.1", // invalid
	})
	wantValid := []string{"10.0.0.0/8", "192.168.1.1", "::1", "2001:db8::/32"}
	if strings.Join(valid, ",") != strings.Join(wantValid, ",") {
		t.Errorf("valid = %v, want %v", valid, wantValid)
	}
	wantInvalid := []string{"notanip", "10.0.0.0/99", "1.2.3.4`", "999.1.1.1"}
	if strings.Join(invalid, ",") != strings.Join(wantInvalid, ",") {
		t.Errorf("invalid = %v, want %v", invalid, wantInvalid)
	}
}

func TestRuleQuote(t *testing.T) {
	if got := ruleQuote("safe.example.com"); got != "safe.example.com" {
		t.Errorf("ruleQuote passthrough changed value: %q", got)
	}
	if got := ruleQuote("a`b`c"); got != "abc" {
		t.Errorf("ruleQuote(%q) = %q, want %q", "a`b`c", got, "abc")
	}
}

// TestHostRuleStripsInjection is the teeth test for the render-time guard: a domain
// carrying a rule-injection payload (which would bypass validation only via a legacy
// or out-of-band row) cannot escape its Host() matcher in the rendered rule. If
// ruleQuote were a no-op the input's two backticks would survive and this fails.
func TestHostRuleStripsInjection(t *testing.T) {
	evil := "evil`) || ClientIP(`0.0.0.0/0"
	got := hostRule([]string{evil})
	if n := strings.Count(got, "`"); n != 2 {
		t.Fatalf("expected exactly 2 delimiter backticks, got %d in %q", n, got)
	}
	if !strings.HasPrefix(got, "Host(`") || !strings.HasSuffix(got, "`)") {
		t.Fatalf("payload escaped the Host() matcher: %q", got)
	}
	if strings.Contains(got, "`) || ClientIP(`") {
		t.Fatalf("injected matcher present: %q", got)
	}
}

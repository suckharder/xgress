package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleInlinesDataFiles(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	_ = os.MkdirAll(rules, 0o755)

	// crs-setup
	must(t, filepath.Join(dir, "crs-setup.conf.example"),
		"# comment\nSecAction \"id:900,phase:1,pass,setvar:tx.x=1\"\n")
	// data file (one with a space — must be dropped — and quote — dropped)
	must(t, filepath.Join(rules, "unix-shell.data"),
		"# header\nwget\ncurl\nrm -rf\nbad\"quote\n")
	must(t, filepath.Join(rules, "ips.data"), "10.0.0.0/8\n192.168.0.0/16\n")
	// a rule using @pmFromFile with a line continuation + Include line
	must(t, filepath.Join(rules, "REQUEST-932.conf"),
		"Include @crs-setup-conf\n"+
			"SecRule ARGS \"@pmFromFile unix-shell.data\" \\\n  \"id:932,phase:2,deny\"\n"+
			"SecRule REMOTE_ADDR \"@ipMatchFromFile ips.data\" \"id:933,phase:1,allow\"\n")

	out, err := Bundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "SecRuleEngine On") {
		t.Error("expected SecRuleEngine On first")
	}
	if strings.Contains(out, "@pmFromFile") || strings.Contains(out, "Include") {
		t.Errorf("pmFromFile/Include not resolved:\n%s", out)
	}
	if !strings.Contains(out, "@pm wget curl bad") && !strings.Contains(out, "@pm wget curl") {
		t.Errorf("expected inlined @pm phrases (single-token only):\n%s", out)
	}
	if strings.Contains(out, "rm -rf") || strings.Contains(out, `bad"quote`) {
		t.Errorf("multi-word / quoted phrases should be dropped:\n%s", out)
	}
	if !strings.Contains(out, "@ipMatch 10.0.0.0/8,192.168.0.0/16") {
		t.Errorf("expected inlined @ipMatch:\n%s", out)
	}
	// continuation joined onto one line.
	if strings.Contains(out, "\\\n") {
		t.Error("line continuations not joined")
	}
}

func must(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

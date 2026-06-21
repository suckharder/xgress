// Command crsbundle turns an OWASP Core Rule Set directory into a single,
// WASM-compatible Coraza directives file.
//
// The Coraza http-wasm Traefik plugin cannot read CRS files from disk
// (`Include @owasp_crs/...` does not work in the WASM build), so to actually run
// the real CRS through that plugin we concatenate crs-setup + the rules and
// resolve the data-file operators inline:
//
//	@pmFromFile foo.data  ->  @pm <phrases from foo.data>
//	@ipMatchFromFile x.data -> @ipMatch <cidrs from x.data>
//
// Phrases containing spaces or quotes are dropped (the inline @pm operator is
// space-separated and unquoted); the result is the bulk of CRS protection in a
// form the WASM plugin accepts. Run at image-build time.
//
// Usage: crsbundle <crs-dir> > crs-bundled.conf
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: crsbundle <crs-dir>")
		os.Exit(2)
	}
	out, err := Bundle(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "crsbundle:", err)
		os.Exit(1)
	}
	fmt.Print(out)
}

// Bundle reads a CRS directory and returns the inlined directives.
func Bundle(dir string) (string, error) {
	dataDir := filepath.Join(dir, "rules")
	if _, err := os.Stat(dataDir); err != nil {
		dataDir = dir // some layouts keep .data next to .conf
	}

	var files []string
	// crs-setup first (defines tx.* thresholds the rules rely on).
	for _, c := range []string{"crs-setup.conf.example", "crs-setup.conf"} {
		if p := filepath.Join(dir, c); exists(p) {
			files = append(files, p)
			break
		}
	}
	// then the rule files in lexical order.
	rules, _ := filepath.Glob(filepath.Join(dir, "rules", "*.conf"))
	sort.Strings(rules)
	files = append(files, rules...)
	if len(files) == 0 {
		return "", fmt.Errorf("no CRS .conf files under %s", dir)
	}

	var b strings.Builder
	b.WriteString("SecRuleEngine On\n")
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		for _, line := range joinContinuations(string(body)) {
			line = processLine(line, dataDir)
			if line != "" {
				b.WriteString(line)
				b.WriteByte('\n')
			}
		}
	}
	return b.String(), nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// joinContinuations merges backslash-continued lines and drops comments/blanks.
func joinContinuations(body string) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if strings.HasSuffix(strings.TrimRight(line, " \t"), "\\") {
			cur.WriteString(strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

var (
	pmFromFile = regexp.MustCompile(`@(?:pmFromFile|pmf)\s+([^"]+)`)
	ipFromFile = regexp.MustCompile(`@(?:ipMatchFromFile|ipMatchF)\s+([^"]+)`)
)

// processLine inlines data-file operators and drops Include lines.
func processLine(line, dataDir string) string {
	if strings.HasPrefix(line, "Include") {
		return "" // we concatenate everything; includes are not resolvable in WASM
	}
	line = pmFromFile.ReplaceAllStringFunc(line, func(m string) string {
		files := strings.Fields(pmFromFile.FindStringSubmatch(m)[1])
		phrases := readData(dataDir, files, false)
		if len(phrases) == 0 {
			return `@pm __xgress_never_match__`
		}
		return "@pm " + strings.Join(phrases, " ")
	})
	line = ipFromFile.ReplaceAllStringFunc(line, func(m string) string {
		files := strings.Fields(ipFromFile.FindStringSubmatch(m)[1])
		ips := readData(dataDir, files, true)
		if len(ips) == 0 {
			return `@ipMatch 192.0.2.0/32`
		}
		return "@ipMatch " + strings.Join(ips, ",")
	})
	return line
}

// readData loads phrases from CRS .data files. For @pm we keep only single-token,
// quote-free phrases (the inline operator is space-separated and unquoted).
func readData(dir string, files []string, isIP bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range files {
		body, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(body)))
		for sc.Scan() {
			p := strings.TrimSpace(sc.Text())
			if p == "" || strings.HasPrefix(p, "#") {
				continue
			}
			if !isIP && (strings.ContainsAny(p, " \t\"") ) {
				continue // would break the unquoted, space-separated @pm operator
			}
			if strings.Contains(p, ",") && isIP {
				continue
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

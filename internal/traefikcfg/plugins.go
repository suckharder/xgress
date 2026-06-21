package traefikcfg

import "github.com/traefik/traefik/v3/pkg/config/dynamic"

// Built-in WAF plugin coordinates. Traefik fetches it from the plugin catalog at
// startup (cached under the persisted plugins-storage). Pinned per xgress release.
// (The server-side cache is handled natively by internal/edge, not a plugin.)
const (
	WAFPluginName    = "coraza"
	WAFModuleName    = "github.com/jcchavezs/coraza-http-wasm-traefik"
	WAFModuleVersion = "v0.2.2"
)

// DefaultWAFDirectives is the "block common exploits" ruleset. The Coraza WASM
// build does not bundle the OWASP CRS, so this is a curated, self-contained
// seclang ruleset covering the common attack classes NPM's snippet targets
// (SQLi, XSS, path traversal, scanners, shell/RCE probes). Operators can replace
// it with their own rules (incl. CRS includes if their plugin build supports them).
func DefaultWAFDirectives() []string {
	return []string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		// Path traversal.
		`SecRule REQUEST_URI "@rx (?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)" "id:1001,phase:1,t:none,t:urlDecodeUni,deny,status:403,log,msg:'Path traversal'"`,
		// SQL injection (common patterns) in URI/args.
		`SecRule REQUEST_URI|ARGS "@rx (?i)(?:union(?:\s+all)?\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|\bor\b\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\()" "id:1002,phase:2,t:none,t:urlDecodeUni,t:lowercase,deny,status:403,log,msg:'SQL injection'"`,
		// XSS probes.
		`SecRule REQUEST_URI|ARGS "@rx (?i)(?:<script|javascript:|onerror\s*=|onload\s*=|<iframe|document\.cookie)" "id:1003,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,msg:'XSS'"`,
		// Shell / RCE / code-eval probes.
		`SecRule ARGS "@rx (?i)(?:base64_decode\s*\(|eval\s*\(|system\s*\(|passthru\s*\(|/etc/passwd|cmd\.exe|\bwget\b|\bcurl\b\s+http)" "id:1004,phase:2,t:none,t:urlDecodeUni,deny,status:403,log,msg:'Remote code/command'"`,
		// Block known bad scanners by user-agent.
		`SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:sqlmap|nikto|nmap|masscan|nessus|acunetix|fimap|dirbuster|wpscan)" "id:1005,phase:1,t:none,deny,status:403,log,msg:'Scanner user-agent'"`,
	}
}

// wafAuditDirectives turn on Coraza's audit log to stdout (captured by the
// supervisor and parsed into security metrics). RelevantOnly logs only
// rule-triggered transactions, so normal traffic isn't logged.
var wafAuditDirectives = []string{
	"SecAuditEngine RelevantOnly",
	"SecAuditLogParts ABIJDEFHKZ",
	"SecAuditLogType Serial",
	"SecAuditLog /dev/stdout",
	"SecAuditLogFormat JSON",
}

// wafMiddleware builds the Coraza plugin middleware from directives, with audit
// logging prepended so blocks surface as security metrics.
func wafMiddleware(directives []string) *dynamic.Middleware {
	if len(directives) == 0 {
		directives = DefaultWAFDirectives()
	}
	full := append(append([]string{}, wafAuditDirectives...), directives...)
	return &dynamic.Middleware{Plugin: map[string]dynamic.PluginConf{
		WAFPluginName: {"directives": full},
	}}
}

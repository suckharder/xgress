package traefikcfg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode"

	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"gopkg.in/yaml.v3"

	"github.com/suckharder/xgress/internal/ssrfguard"
)

// BuildMiddleware constructs a real dynamic.Middleware from a middleware type
// (the Traefik JSON key, e.g. "headers", "basicAuth", "ipAllowList") and a
// params map. It does this by composing the JSON object {type: params} and
// strictly decoding it into Traefik's own struct with unknown-field rejection —
// giving us genuine, struct-accurate linting with zero hand-maintained schema.
func BuildMiddleware(mwType string, params map[string]any) (*dynamic.Middleware, error) {
	if mwType == "" {
		return nil, fmt.Errorf("middleware type is required")
	}
	wrapper := map[string]any{mwType: params}
	raw, err := json.Marshal(wrapper)
	if err != nil {
		return nil, err
	}
	mw, err := strictDecodeMiddleware(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s middleware: %w", mwType, err)
	}
	return mw, nil
}

func strictDecodeMiddleware(raw []byte) (*dynamic.Middleware, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var mw dynamic.Middleware
	if err := dec.Decode(&mw); err != nil {
		return nil, humanizeJSONErr(err)
	}
	return &mw, nil
}

// ValidationIssue is a single problem found while linting a host/middleware
// before it is persisted or served.
type ValidationIssue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidateMiddleware checks a middleware definition against the real struct.
func ValidateMiddleware(mwType string, params map[string]any) []ValidationIssue {
	if _, err := BuildMiddleware(mwType, params); err != nil {
		return []ValidationIssue{{Field: mwType, Message: err.Error()}}
	}
	return nil
}

// UpstreamLike is the minimal view of an upstream the host validator needs.
// Exported so the API layer can adapt store types without a cyclic import.
type UpstreamLike interface {
	GetScheme() string
	GetHost() string
}

// ValidateHostInputs performs semantic validation on user-supplied host data
// that the type system alone cannot catch (valid URLs, non-empty domains, …).
func ValidateHostInputs[T UpstreamLike](kind string, domains []string, upstreams []T, redirectTo string) []ValidationIssue {
	var issues []ValidationIssue
	switch kind {
	case "proxy":
		if len(domains) == 0 {
			issues = append(issues, ValidationIssue{Field: "domains", Message: "at least one domain is required"})
		}
		if len(upstreams) == 0 {
			issues = append(issues, ValidationIssue{Field: "upstreams", Message: "at least one upstream is required"})
		}
		for i, u := range upstreams {
			if u.GetHost() == "" {
				issues = append(issues, ValidationIssue{Field: fmt.Sprintf("upstreams[%d].host", i), Message: "host is required"})
			}
			if s := u.GetScheme(); s != "" && s != "http" && s != "https" && s != "h2c" {
				issues = append(issues, ValidationIssue{Field: fmt.Sprintf("upstreams[%d].scheme", i), Message: "scheme must be http, https, or h2c"})
			}
		}
	case "redirection":
		if len(domains) == 0 {
			issues = append(issues, ValidationIssue{Field: "domains", Message: "at least one domain is required"})
		}
		if redirectTo == "" {
			issues = append(issues, ValidationIssue{Field: "redirectTo", Message: "redirect target is required"})
		} else if _, err := url.ParseRequestURI(redirectTo); err != nil {
			issues = append(issues, ValidationIssue{Field: "redirectTo", Message: "must be a valid absolute URL"})
		}
	}
	// NOTE: per-domain character validation is centralized in ValidateRuleInputs
	// (called for every host kind/mode), so it isn't repeated here.
	return issues
}

// validDomain reports whether d is acceptable as a Host()/HostSNI() rule value.
// Lenient by design so internationalized domains keep working: any Unicode letter
// or digit is allowed, plus '.', '-', '_' and '*' (wildcard certs). Everything else
// — backticks, whitespace, slashes, and rule metacharacters like ()|&, — is
// rejected. This closes the router-rule injection vector (a backtick would otherwise
// break out of the backtick-delimited matcher) while preserving real hostnames.
func validDomain(d string) bool {
	if strings.TrimSpace(d) == "" {
		return false
	}
	for _, r := range d {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r == '.' || r == '-' || r == '_' || r == '*' {
			continue
		}
		return false
	}
	return true
}

// validPathPrefix reports whether p is acceptable as a PathPrefix() rule value: an
// absolute path (leading '/') containing no backtick, whitespace, or control
// character. Other path-legal characters (parentheses, percent-encoding, etc.) are
// fine — they live inside the backtick-delimited value, not the rule structure.
func validPathPrefix(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for _, r := range p {
		if r == '`' || r < 0x20 || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

// ValidateRuleInputs validates every user-supplied value that the renderer
// interpolates into a Traefik router *rule string* — host domains (Host/HostSNI)
// and location path prefixes (PathPrefix). It is called for all host kinds and
// composition modes so no path can skip it. Empty entries are ignored (the renderer
// skips them, and "at least one domain" is enforced per-kind elsewhere).
func ValidateRuleInputs(domains []string, pathPrefixes []string) []ValidationIssue {
	var issues []ValidationIssue
	for i, d := range domains {
		if d == "" {
			continue
		}
		if !validDomain(d) {
			issues = append(issues, ValidationIssue{
				Field:   fmt.Sprintf("domains[%d]", i),
				Message: "invalid domain — letters, digits, '.', '-', '_' and '*' only",
			})
		}
	}
	for i, p := range pathPrefixes {
		if p == "" {
			continue
		}
		if !validPathPrefix(p) {
			issues = append(issues, ValidationIssue{
				Field:   fmt.Sprintf("locations[%d].pathPrefix", i),
				Message: "path must start with '/' and contain no backticks or whitespace",
			})
		}
	}
	return issues
}

// ParseAllowIPs splits IP/CIDR allow-list entries into the valid (trimmed) ones and
// the invalid ones. Empty/whitespace entries are dropped. Access-list allow-lists
// feed both Traefik's ipAllowList middleware (where a malformed value fails the whole
// middleware build) and the satisfy-any ClientIP() rule, so callers reject when any
// entry is invalid.
func ParseAllowIPs(in []string) (valid, invalid []string) {
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if net.ParseIP(c) != nil {
			valid = append(valid, c)
			continue
		}
		if _, _, err := net.ParseCIDR(c); err == nil {
			valid = append(valid, c)
			continue
		}
		invalid = append(invalid, c)
	}
	return valid, invalid
}

// ValidateConfig round-trips a rendered configuration through strict decoding to
// catch any structural problem before it is served to Traefik. Because we built
// the config from real structs this should always pass, but it is a cheap
// last-line guard that also detects programming mistakes in the renderer.
func ValidateConfig(cfg *dynamic.Configuration) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var back dynamic.Configuration
	if err := dec.Decode(&back); err != nil {
		return humanizeJSONErr(err)
	}
	return nil
}

// ParseRawConfig parses user-supplied raw dynamic configuration (YAML) into the
// real Traefik structs and validates it. Returns nil for empty input. Used by
// the "raw passthrough" advanced feature — untrusted input is parsed against the
// real types so a bad snippet is rejected before it can reach Traefik.
func ParseRawConfig(rawYAML string) (*dynamic.Configuration, error) {
	if strings.TrimSpace(rawYAML) == "" {
		return nil, nil
	}
	var cfg dynamic.Configuration
	// KnownFields(true) makes YAML reject unknown keys too — without it yaml
	// silently drops them and a typo'd field would slip through.
	dec := yaml.NewDecoder(strings.NewReader(rawYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", humanizeJSONErr(err))
	}
	if err := ValidateConfig(&cfg); err != nil {
		return nil, err
	}
	if err := checkReservedPriorities(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ReservedRouterPriority is the floor of the priority band xgress reserves for its
// own system routers (ACME HTTP-01 at 1_000_000, the fail2ban deny at 2_000_000).
// User-authored raw routers must stay below it so they can't shadow those.
const ReservedRouterPriority = 1_000_000

// CheckRawServiceTargets rejects raw config that aims an HTTP service's
// load-balancer server at a loopback/link-local/metadata address (e.g. xgress's own
// provider/admin loopback servers or 169.254.169.254). Structured proxy upstreams
// are intentionally NOT checked here — proxying to internal/private hosts is the
// normal reverse-proxy use case; this guards only the raw-passthrough escape hatch.
// It performs DNS resolution, so call it at save time, never per render.
func CheckRawServiceTargets(cfg *dynamic.Configuration) error {
	if cfg == nil || cfg.HTTP == nil {
		return nil
	}
	for name, svc := range cfg.HTTP.Services {
		if svc == nil || svc.LoadBalancer == nil {
			continue
		}
		for _, srv := range svc.LoadBalancer.Servers {
			if srv.URL == "" {
				continue
			}
			if err := ssrfguard.CheckURL(srv.URL); err != nil {
				return fmt.Errorf("service %q: %w", name, err)
			}
		}
	}
	return nil
}

// checkReservedPriorities rejects raw routers that would outrank xgress's system
// routers (priority-shadowing the ACME challenge or the banned-IP deny).
func checkReservedPriorities(cfg *dynamic.Configuration) error {
	if cfg.HTTP != nil {
		for name, r := range cfg.HTTP.Routers {
			if r != nil && r.Priority >= ReservedRouterPriority {
				return fmt.Errorf("router %q: priority %d is reserved for xgress system routers; use a value below %d", name, r.Priority, ReservedRouterPriority)
			}
		}
	}
	if cfg.TCP != nil {
		for name, r := range cfg.TCP.Routers {
			if r != nil && r.Priority >= ReservedRouterPriority {
				return fmt.Errorf("tcp router %q: priority %d is reserved for xgress system routers; use a value below %d", name, r.Priority, ReservedRouterPriority)
			}
		}
	}
	return nil
}

func humanizeJSONErr(err error) error {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "json: ")
	return fmt.Errorf("%s", msg)
}

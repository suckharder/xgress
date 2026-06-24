// Package waf builds the native, in-process Coraza Web Application Firewall used
// by xgress. The engine is a pure-Go library (github.com/corazawaf/coraza/v3)
// running directly inside the xgress binary — there is no WebAssembly, no wazero
// JIT, no Traefik plugin, and no plugin-catalog fetch. The OWASP Core Rule Set is
// embedded at build time via github.com/corazawaf/coraza-coreruleset/v4 (an
// io/fs), so the WAF is always present and fully air-gapped.
//
// The request path that drives transactions lives in internal/edge; this package
// only constructs and configures the coraza.WAF instance from the operator's
// settings (paranoia level, anomaly threshold, an optional request-body limit,
// and any extra custom seclang directives).
package waf

import (
	"fmt"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Defaults for the tunable WAF parameters. Paranoia level 1 is the OWASP CRS
// default and keeps false positives low; the request-body limit bounds how much
// of a request body Coraza buffers for inspection (the old WASM build's unbounded
// body access was implicated in the crashes, so native Coraza is kept bounded).
const (
	DefaultParanoiaLevel        = 1
	DefaultAnomalyThreshold     = 5
	DefaultRequestBodyLimit     = 128 * 1024 // bytes
	MaxParanoiaLevel            = 4
	overrideRuleID              = 90000000 // custom, outside CRS's 9xxxxx ranges
	responseBodyInspectionLimit = 512 * 1024
)

// Options configures a WAF build. Zero values fall back to the package defaults.
type Options struct {
	ParanoiaLevel         int      // 1..4 (CRS blocking_paranoia_level)
	AnomalyThreshold      int      // CRS inbound_anomaly_score_threshold
	RequestBodyLimitBytes int      // max request body bytes buffered for inspection
	Extra                 []string // custom seclang directives appended after the CRS
}

func (o Options) normalize() Options {
	if o.ParanoiaLevel < 1 {
		o.ParanoiaLevel = DefaultParanoiaLevel
	}
	if o.ParanoiaLevel > MaxParanoiaLevel {
		o.ParanoiaLevel = MaxParanoiaLevel
	}
	if o.AnomalyThreshold < 1 {
		o.AnomalyThreshold = DefaultAnomalyThreshold
	}
	if o.RequestBodyLimitBytes <= 0 {
		o.RequestBodyLimitBytes = DefaultRequestBodyLimit
	}
	return o
}

// Directives renders the full seclang configuration string for the given
// options. It is exported so tests can assert the assembled config without
// constructing a full WAF.
func Directives(o Options) string {
	o = o.normalize()
	lines := []string{
		// Base engine config + variables from Coraza's recommended file.
		"Include @coraza.conf-recommended",
		// Recommended ships SecRuleEngine DetectionOnly and a 12.5MB body limit;
		// override to actually block and to bound buffered memory.
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		fmt.Sprintf("SecRequestBodyLimit %d", o.RequestBodyLimitBytes),
		fmt.Sprintf("SecRequestBodyInMemoryLimit %d", o.RequestBodyLimitBytes),
		// ProcessPartial (not Reject): inspect bodies up to the limit, then let the
		// rest through. Keeps memory bounded without 403-ing legitimate large
		// uploads/responses on a general-purpose proxy.
		"SecRequestBodyLimitAction ProcessPartial",
		"SecResponseBodyAccess On",
		fmt.Sprintf("SecResponseBodyLimit %d", responseBodyInspectionLimit),
		"SecResponseBodyLimitAction ProcessPartial",
		// CRS tunables + default thresholds.
		"Include @crs-setup.conf.example",
		// Pin paranoia + anomaly threshold BEFORE the rules load. CRS's
		// REQUEST-901-INITIALIZATION only sets defaults when unset, so setting them
		// here (phase 1, ahead of the rule files) makes them authoritative. The rule
		// ID is well outside CRS's 9xxxxx ranges to avoid a duplicate-ID parse error.
		fmt.Sprintf(`SecAction "id:%d,phase:1,nolog,pass,t:none,`+
			`setvar:tx.blocking_paranoia_level=%d,`+
			`setvar:tx.detection_paranoia_level=%d,`+
			`setvar:tx.inbound_anomaly_score_threshold=%d"`,
			overrideRuleID, o.ParanoiaLevel, o.ParanoiaLevel, o.AnomalyThreshold),
		// The OWASP Core Rule Set itself.
		"Include @owasp_crs/*.conf",
	}
	lines = append(lines, o.Extra...)
	return strings.Join(lines, "\n")
}

// Build constructs a Coraza WAF from the embedded OWASP CRS and the given
// options. errCb, if non-nil, is invoked for every matched rule (used to feed
// security metrics). The returned WAF is concurrency-safe and reusable across
// requests; rebuild a fresh one (and swap it in atomically) when settings change.
func Build(o Options, errCb func(types.MatchedRule)) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(Directives(o))
	if errCb != nil {
		cfg = cfg.WithErrorCallback(errCb)
	}
	w, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("build coraza waf: %w", err)
	}
	return w, nil
}

package edge

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	coraza "github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/suckharder/xgress/internal/secmetrics"
)

// wafState holds the hot-swappable Coraza engine plus the on/off toggles. The
// engine is rebuilt and swapped atomically when WAF settings change, so requests
// in flight keep using the WAF they started with.
type wafState struct {
	mu  sync.RWMutex
	waf coraza.WAF
}

func (s *wafState) set(w coraza.WAF) {
	s.mu.Lock()
	s.waf = w
	s.mu.Unlock()
}

func (s *wafState) get() coraza.WAF {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.waf
}

// SetWAF swaps in a freshly built Coraza engine (or nil to disable). Safe to call
// at runtime; subsequent requests pick up the new engine.
func (s *Server) SetWAF(w coraza.WAF) { s.waf.set(w) }

// SetEnabled updates the global WAF/cache feature flags (called by the engine on
// every reload). Per-host opt-in is still gated by h.WAF / h.Cache.
func (s *Server) SetEnabled(waf, cache bool) {
	s.wafEnabled.Store(waf)
	s.cacheEnabled.Store(cache)
}

// SetSecMetrics wires the security-metrics collector that WAF detections feed.
func (s *Server) SetSecMetrics(c *secmetrics.Collector) { s.sec = c }

// wafActive reports whether the WAF should run for a host (global on + engine built).
func (s *Server) wafActive() bool { return s.wafEnabled.Load() && s.waf.get() != nil }

// wafResult is the outcome of a WAF phase: status>0 means block with that code.
type wafResult struct {
	status  int
	blocked bool
}

func pass() wafResult          { return wafResult{} }
func block(code int) wafResult { return wafResult{status: code, blocked: true} }
func failClosed() wafResult    { return wafResult{status: http.StatusInternalServerError, blocked: true} }

// statusFromInterruption maps a Coraza interruption to an HTTP status (deny→its
// status or 403; redirect→its status).
func statusFromInterruption(it *types.Interruption) int {
	if it.Status != 0 {
		return it.Status
	}
	return http.StatusForbidden
}

// wafRequest drives the request-phase transaction (connection, URI, headers,
// body) mirroring coraza/v3/http's processRequest, but using the real client IP
// from X-Forwarded-For. On a body-bearing request it consumes r.Body for
// inspection and transparently reinstates it (buffered + remainder) for the
// upstream. Returns block/pass; an internal processing error fails closed.
func (s *Server) wafRequest(tx types.Transaction, r *http.Request) wafResult {
	client, cport := clientAddr(r)
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vv := range r.Header {
		for _, v := range vv {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host) // Go promotes Host out of the header map
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return block(statusFromInterruption(it))
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			s.log.Warn("waf: read request body", "err", err)
			return failClosed()
		}
		if it != nil {
			return block(statusFromInterruption(it))
		}
		if rbr, err := tx.RequestBodyReader(); err == nil {
			// Reinstate the body for the upstream: buffered bytes + anything beyond
			// the inspection limit (ProcessPartial leaves the remainder in r.Body).
			body := r.Body
			r.Body = readCloser{io.MultiReader(rbr, body), body}
		}
	}
	if it, err := tx.ProcessRequestBody(); err != nil {
		s.log.Warn("waf: process request body", "err", err)
		return failClosed()
	} else if it != nil {
		return block(statusFromInterruption(it))
	}
	return pass()
}

// wafResponse drives the response-phase transaction on a fully-buffered response.
// Rule interruptions block (fail closed); internal processing errors are logged
// and the response is served (fail open) so a WAF quirk can't nuke valid traffic.
func (s *Server) wafResponse(tx types.Transaction, cr *cachedResponse) wafResult {
	for k, vv := range cr.Header {
		for _, v := range vv {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(cr.Status, "HTTP/1.1"); it != nil {
		return block(statusFromInterruption(it))
	}
	if tx.IsResponseBodyAccessible() && tx.IsResponseBodyProcessable() {
		if it, _, err := tx.ReadResponseBodyFrom(bytes.NewReader(cr.Body)); err != nil {
			s.log.Warn("waf: read response body", "err", err)
			return s.wafResponseFailMode()
		} else if it != nil {
			return block(statusFromInterruption(it))
		}
		if it, err := tx.ProcessResponseBody(); err != nil {
			s.log.Warn("waf: process response body", "err", err)
			return s.wafResponseFailMode()
		} else if it != nil {
			return block(statusFromInterruption(it))
		}
	}
	return pass()
}

// recordTx pushes one security-metrics event per matched rule (with full request
// context), then runs phase-5 logging and closes the transaction. Call once per
// request, after all phases, e.g. via defer.
func (s *Server) recordTx(tx types.Transaction, r *http.Request) {
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	// Only blocked transactions are recorded as security events — a clean,
	// trustworthy "blocked attacks" feed. CRS evaluates many non-blocking
	// initialization/protocol/scoring rules on every request; surfacing those (or
	// sub-threshold detections) would swamp the dashboard with noise.
	if s.sec == nil || !tx.IsInterrupted() {
		return
	}
	host := hostOnly(r.Host)
	clientFallback, _ := clientAddr(r)
	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		// Record the genuine attack rules that contributed to the block (they carry
		// an "attack-*" tag: attack-sqli, attack-xss, attack-rce, …), not CRS's
		// internal init/setup/anomaly-scoring rules.
		if rule.ID() == 0 || !hasAttackTag(rule.Tags()) {
			continue
		}
		ip := mr.ClientIPAddress()
		if ip == "" {
			ip = clientFallback
		}
		s.sec.Record(secmetrics.Event{
			At: time.Now(), ClientIP: ip, Host: host, Method: r.Method, URI: r.URL.RequestURI(),
			RuleID:   strconv.Itoa(rule.ID()),
			Message:  mr.Message(),
			Category: secmetrics.Category(rule.Tags(), mr.Message()),
			Severity: rule.Severity().Int(),
			Blocked:  true, // only interrupted transactions reach here
		})
	}
}

// hasAttackTag reports whether any CRS tag marks this as an attack-category rule
// (e.g. "attack-sqli"), distinguishing real detections from CRS's per-request
// initialization/setup/scoring rules.
func hasAttackTag(tags []string) bool {
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") {
			return true
		}
	}
	return false
}

// writeBlocked writes a WAF block response with the interruption's status.
func writeBlocked(w http.ResponseWriter, status int) {
	if status == 0 {
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}

// readCloser pairs a reader (the reconstructed body) with the original closer.
type readCloser struct {
	io.Reader
	io.Closer
}

// clientAddr extracts the real client IP + port, preferring the left-most
// X-Forwarded-For value injected by Traefik (so CRS rules and auto-bans see the
// actual client, not the loopback hop), falling back to RemoteAddr.
func clientAddr(r *http.Request) (string, int) {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(xff)
		if i := strings.IndexByte(ip, ','); i >= 0 {
			ip = strings.TrimSpace(ip[:i])
		}
		if ip != "" {
			return ip, 0
		}
	}
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, 0
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

// hostOnly strips any port from a Host header value.
func hostOnly(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

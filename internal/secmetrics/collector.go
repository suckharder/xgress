// Package secmetrics turns the Coraza WAF's log output (captured from Traefik's
// stdout by the supervisor) into security metrics: blocked-request counts, top
// triggered rules, attack categories, source IPs, per-host totals, a time
// series, and a recent-events feed. The parser is tolerant of both the Coraza
// JSON audit format and ModSecurity-style `[id "…"][msg "…"]` text, because the
// JSON format is not always honoured by the WASM build.
package secmetrics

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is one WAF detection/block.
type Event struct {
	At       time.Time `json:"at"`
	ClientIP string    `json:"clientIp"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	RuleID   string    `json:"ruleId"`
	Message  string    `json:"message"`
	Category string    `json:"category"`
	Severity int       `json:"severity"`
	Blocked  bool      `json:"blocked"`
}

// Collector aggregates WAF events. Safe for concurrent use. State is in-memory
// (resets on restart) — these are live operational metrics, not an audit store.
type Collector struct {
	mu         sync.Mutex
	total      int
	blocked    int
	byRule     map[string]*counter
	byCategory map[string]int
	byIP       map[string]int
	byHost     map[string]int
	hourly     map[int64]int // unix hour -> count
	recent     []Event       // newest last
	startedAt  time.Time
	observers  []func(Event) // notified on each event (e.g. auto-ban evaluator)
	events     chan Event    // bounded queue drained by a single worker goroutine
}

// AddObserver registers a callback invoked for every parsed WAF event.
func (c *Collector) AddObserver(fn func(Event)) {
	c.mu.Lock()
	c.observers = append(c.observers, fn)
	c.mu.Unlock()
}

type counter struct {
	count int
	msg   string
}

const recentMax = 200

// Cardinality bounds for the request-driven maps. byIP (client IP) and byHost
// (Host header) keys come from traffic, so a sustained flood of distinct values
// would otherwise grow them without limit (a slow memory leak). We cap the
// distinct-key count and evict the lowest-count keys when over the cap — Snapshot
// only ever surfaces the top 10, so dropping long-tail singletons loses nothing
// visible, and the heavy hitters (high counts) always survive. byRule/byCategory
// are bounded by the ruleset / fixed attack taxonomy, so they need no cap.
const (
	maxCountKeys   = 50000 // evict a count map once it exceeds this many keys…
	keepCountKeys  = 40000 // …down to this many highest-count keys
	maxHourBuckets = 48    // keep ~2 days of hourly buckets (chart shows last 24h)
)

// observerQueue bounds how many WAF events can be in flight to observers. Under a
// WAF flood, excess events are dropped (metrics are still counted) rather than
// spawning unbounded goroutines / DB load — see notifyObservers / runObservers.
const observerQueue = 1024

// New constructs a Collector and starts its single observer-dispatch worker.
func New() *Collector {
	c := &Collector{
		byRule: map[string]*counter{}, byCategory: map[string]int{},
		byIP: map[string]int{}, byHost: map[string]int{}, hourly: map[int64]int{},
		startedAt: time.Now(),
		events:    make(chan Event, observerQueue),
	}
	go c.runObservers()
	return c
}

// runObservers is the single goroutine that delivers events to observers, so an
// attacker-driven WAF flood can never spawn unbounded goroutines. Each observer
// call is panic-guarded so one bad observer can't crash the worker (or the process).
func (c *Collector) runObservers() {
	for e := range c.events {
		c.mu.Lock()
		obs := make([]func(Event), len(c.observers))
		copy(obs, c.observers)
		c.mu.Unlock()
		for _, fn := range obs {
			func() {
				defer func() { _ = recover() }()
				fn(e)
			}()
		}
	}
}

var (
	reID   = regexp.MustCompile(`\[id "(\d+)"\]`)
	reMsg  = regexp.MustCompile(`\[msg "([^"]*)"\]`)
	reIP   = regexp.MustCompile(`\[client "?([0-9a-fA-F:.]+)`)
	reURI  = regexp.MustCompile(`\[uri "([^"]*)"\]`)
	reHost = regexp.MustCompile(`\[hostname "([^"]+)"\]`)
)

// Ingest parses a single captured log line. Non-WAF lines are ignored cheaply.
func (c *Collector) Ingest(raw string, at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	// Cheap prefilter: only lines that look like Coraza audit/error output.
	jsonish := strings.Contains(raw, `"transaction"`) || strings.Contains(raw, `"messages"`)
	textish := strings.Contains(raw, `[id "`)
	if !jsonish && !textish {
		return
	}
	if jsonish {
		if evs, ok := parseJSON(raw, at); ok {
			for _, e := range evs {
				c.add(e)
			}
			return
		}
	}
	if textish {
		if e, ok := parseText(raw, at); ok {
			c.add(e)
		}
	}
}

// parseJSON parses a Coraza JSON audit entry into one event per matched rule.
func parseJSON(raw string, at time.Time) ([]Event, bool) {
	i := strings.IndexByte(raw, '{')
	if i < 0 {
		return nil, false
	}
	var doc struct {
		Transaction struct {
			ClientIP string `json:"client_ip"`
			Request  struct {
				Method  string          `json:"method"`
				URI     string          `json:"uri"`
				Headers json.RawMessage `json:"headers"`
			} `json:"request"`
			Response struct {
				Status int `json:"status"`
			} `json:"response"`
			IsInterrupted bool `json:"is_interrupted"`
			Messages      []struct {
				Message string `json:"message"`
				Data    struct {
					ID       int      `json:"id"`
					Msg      string   `json:"msg"`
					Severity int      `json:"severity"`
					Tags     []string `json:"tags"`
				} `json:"data"`
			} `json:"messages"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal([]byte(raw[i:]), &doc); err != nil {
		return nil, false
	}
	t := doc.Transaction
	if len(t.Messages) == 0 {
		return nil, false
	}
	host := hostFromHeaders(t.Request.Headers)
	blocked := t.IsInterrupted || t.Response.Status == 403
	var out []Event
	for _, m := range t.Messages {
		msg := m.Data.Msg
		if msg == "" {
			msg = m.Message
		}
		out = append(out, Event{
			At: at, ClientIP: t.ClientIP, Host: host, Method: t.Request.Method, URI: t.Request.URI,
			RuleID: strconv.Itoa(m.Data.ID), Message: msg, Category: category(m.Data.Tags, msg),
			Severity: m.Data.Severity, Blocked: blocked,
		})
	}
	return out, true
}

func hostFromHeaders(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Headers may be map[string]string or map[string][]string.
	var asStr map[string]string
	if json.Unmarshal(raw, &asStr) == nil {
		for k, v := range asStr {
			if strings.EqualFold(k, "host") {
				return v
			}
		}
	}
	var asArr map[string][]string
	if json.Unmarshal(raw, &asArr) == nil {
		for k, v := range asArr {
			if strings.EqualFold(k, "host") && len(v) > 0 {
				return v[0]
			}
		}
	}
	return ""
}

func parseText(raw string, at time.Time) (Event, bool) {
	id := reID.FindStringSubmatch(raw)
	if id == nil {
		return Event{}, false
	}
	e := Event{At: at, RuleID: id[1], Blocked: true}
	if m := reMsg.FindStringSubmatch(raw); m != nil {
		e.Message = m[1]
	}
	if m := reIP.FindStringSubmatch(raw); m != nil {
		e.ClientIP = m[1]
	}
	if m := reURI.FindStringSubmatch(raw); m != nil {
		e.URI = m[1]
	}
	if m := reHost.FindStringSubmatch(raw); m != nil {
		e.Host = m[1]
	}
	e.Category = category(nil, e.Message)
	return e, true
}

// category derives a friendly attack category from CRS tags or the message text.
func category(tags []string, msg string) string {
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") {
			return strings.TrimPrefix(t, "attack-")
		}
	}
	l := strings.ToLower(msg)
	switch {
	case strings.Contains(l, "sql"):
		return "sqli"
	case strings.Contains(l, "xss") || strings.Contains(l, "cross-site"):
		return "xss"
	case strings.Contains(l, "traversal") || strings.Contains(l, "lfi") || strings.Contains(l, "file"):
		return "lfi"
	case strings.Contains(l, "rce") || strings.Contains(l, "command") || strings.Contains(l, "code"):
		return "rce"
	case strings.Contains(l, "scanner") || strings.Contains(l, "user-agent"):
		return "scanner"
	case strings.Contains(l, "protocol"):
		return "protocol"
	default:
		return "other"
	}
}

func (c *Collector) add(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if e.Blocked {
		c.blocked++
	}
	if e.RuleID != "" {
		cr := c.byRule[e.RuleID]
		if cr == nil {
			cr = &counter{}
			c.byRule[e.RuleID] = cr
		}
		cr.count++
		if cr.msg == "" {
			cr.msg = e.Message
		}
	}
	if e.Category != "" {
		c.byCategory[e.Category]++
	}
	if e.ClientIP != "" {
		c.byIP[e.ClientIP]++
	}
	if e.Host != "" {
		c.byHost[e.Host]++
	}
	c.hourly[e.At.Truncate(time.Hour).Unix()]++
	c.recent = append(c.recent, e)
	if len(c.recent) > recentMax {
		c.recent = c.recent[len(c.recent)-recentMax:]
	}
	// Bound the request-driven maps so a distinct-value flood can't leak memory.
	capCounts(c.byIP, maxCountKeys, keepCountKeys)
	capCounts(c.byHost, maxCountKeys, keepCountKeys)
	capOldestHours(c.hourly, maxHourBuckets)
	// Hand off to the single observer worker (non-blocking: drop on overflow so a
	// WAF flood can't unboundedly grow goroutines / DB load). The send is to a
	// buffered channel and never blocks, so holding the lock here is safe.
	if len(c.observers) > 0 {
		select {
		case c.events <- e:
		default: // queue full — drop this event's observer notification
		}
	}
}

// capCounts bounds a count map's cardinality: once it exceeds max keys, evict the
// lowest-count keys down to keep. The O(n log n) sort runs only on the rare eviction
// (when the map crosses the cap); otherwise this is a single length check. The
// highest-count keys (the ones Snapshot surfaces) always survive. Caller holds c.mu.
func capCounts(m map[string]int, max, keep int) {
	if len(m) <= max {
		return
	}
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v }) // highest count first
	for _, e := range all[keep:] {
		delete(m, e.k)
	}
}

// capOldestHours keeps only the most recent `keep` hourly buckets (the 24h chart
// never reads older ones). Caller holds c.mu.
func capOldestHours(m map[int64]int, keep int) {
	if len(m) <= keep {
		return
	}
	hours := make([]int64, 0, len(m))
	for h := range m {
		hours = append(hours, h)
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i] > hours[j] }) // newest first
	for _, h := range hours[keep:] {
		delete(m, h)
	}
}

// NamedCount is a labelled count for top-N lists.
type NamedCount struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

// TimePoint is one hourly bucket of the time series.
type TimePoint struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// Snapshot is the aggregated view returned to the API.
type Snapshot struct {
	Total      int          `json:"total"`
	Blocked    int          `json:"blocked"`
	SinceHours int          `json:"sinceHours"`
	TopRules   []NamedCount `json:"topRules"`
	Categories []NamedCount `json:"categories"`
	TopIPs     []NamedCount `json:"topIps"`
	TopHosts   []NamedCount `json:"topHosts"`
	Series     []TimePoint  `json:"series"`
	Recent     []Event      `json:"recent"`
}

// Snapshot returns the current aggregates (last-24h series, newest events first).
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{Total: c.total, Blocked: c.blocked, SinceHours: 24}

	s.TopRules = topRules(c.byRule, 10)
	s.Categories = topN(c.byCategory, 10)
	s.TopIPs = topN(c.byIP, 10)
	s.TopHosts = topN(c.byHost, 10)

	now := time.Now().Truncate(time.Hour)
	for i := 23; i >= 0; i-- {
		h := now.Add(time.Duration(-i) * time.Hour)
		s.Series = append(s.Series, TimePoint{Hour: h.Format("15:04"), Count: c.hourly[h.Unix()]})
	}
	// Recent newest-first.
	s.Recent = make([]Event, len(c.recent))
	for i, e := range c.recent {
		s.Recent[len(c.recent)-1-i] = e
	}
	return s
}

func topRules(m map[string]*counter, n int) []NamedCount {
	out := make([]NamedCount, 0, len(m))
	for k, v := range m {
		out = append(out, NamedCount{Name: k, Label: v.msg, Count: v.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topN(m map[string]int, n int) []NamedCount {
	out := make([]NamedCount, 0, len(m))
	for k, v := range m {
		out = append(out, NamedCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

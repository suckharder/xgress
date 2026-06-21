// Package webcontent serves xgress-rendered HTML to Traefik over the loopback
// provider server: the "Default Site" page for unknown hosts (#1) and per-host
// custom error pages (#2). Traefik routes to these via a catch-all router and an
// `errors` middleware respectively; the actual content is owned by xgress and read
// from the database, so it changes with no Traefik restart.
package webcontent

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/suckharder/xgress/internal/store"
)

// Settings keys for the Default Site behavior.
const (
	KeyDefaultMode       = "defaultsite.mode"       // 404 | redirect | custom | welcome | close
	KeyDefaultRedirectTo = "defaultsite.redirectTo" //
	KeyDefaultHTML       = "defaultsite.html"       // custom HTML
	KeyDefaultStatus     = "defaultsite.statusCode" // status for custom/404 modes
)

// Path prefixes the responder answers on (under the loopback provider server).
const (
	DefaultPath = "/__xgress/default"
	ErrorPath   = "/__xgress/error/" // /__xgress/error/{hostID}/{status}
	BannedPath  = "/__xgress/banned" // 403 for banned source IPs
)

// Responder serves default-site and error content from the store.
type Responder struct {
	st *store.Store
}

// New constructs a Responder.
func New(st *store.Store) *Responder { return &Responder{st: st} }

// Register wires the responder routes onto a mux.
func (r *Responder) Register(mux *http.ServeMux) {
	mux.HandleFunc(DefaultPath, r.handleDefault)
	mux.HandleFunc(ErrorPath, r.handleError)
	mux.HandleFunc(BannedPath, r.handleBanned)
}

func (r *Responder) handleBanned(w http.ResponseWriter, req *http.Request) {
	writeStatusPage(w, http.StatusForbidden, bannedHTML)
}

func (r *Responder) handleDefault(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	mode := r.setting(ctx, KeyDefaultMode, "404")
	switch mode {
	case "redirect":
		to := r.setting(ctx, KeyDefaultRedirectTo, "")
		if to == "" {
			writeStatusPage(w, 404, "")
			return
		}
		http.Redirect(w, req, to, http.StatusFound)
	case "custom":
		status := atoiDefault(r.setting(ctx, KeyDefaultStatus, "200"), 200)
		writeStatusPage(w, status, r.setting(ctx, KeyDefaultHTML, ""))
	case "welcome":
		writeStatusPage(w, 200, welcomeHTML)
	case "close":
		// Best-effort "no response": hijack and close the connection.
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusTeapot)
	default: // 404
		status := atoiDefault(r.setting(ctx, KeyDefaultStatus, "404"), 404)
		writeStatusPage(w, status, "")
	}
}

func (r *Responder) handleError(w http.ResponseWriter, req *http.Request) {
	// Path: /__xgress/error/{hostID}/{status}
	rest := strings.TrimPrefix(req.URL.Path, ErrorPath)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, req)
		return
	}
	hostID, statusStr := parts[0], parts[1]
	status := atoiDefault(statusStr, 500)
	host, err := r.st.GetHost(req.Context(), hostID)
	if err != nil {
		writeStatusPage(w, status, "")
		return
	}
	for _, ep := range host.ErrorPages {
		if statusMatches(ep.Status, status) {
			writeStatusPage(w, status, ep.HTML)
			return
		}
	}
	writeStatusPage(w, status, "")
}

func (r *Responder) setting(ctx context.Context, key, def string) string {
	v, err := r.st.GetSetting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	return v
}

// statusMatches reports whether a status code matches an ErrorPage.Status spec
// like "404", "500,502", or "500-599".
func statusMatches(spec string, code int) bool {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo := atoiDefault(strings.TrimSpace(bounds[0]), -1)
			hi := atoiDefault(strings.TrimSpace(bounds[1]), -1)
			if lo >= 0 && hi >= 0 && code >= lo && code <= hi {
				return true
			}
		} else if atoiDefault(part, -1) == code {
			return true
		}
	}
	return false
}

func writeStatusPage(w http.ResponseWriter, status int, html string) {
	if html == "" {
		html = defaultStatusHTML(status)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(html))
}

func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}

func defaultStatusHTML(status int) string {
	title := strconv.Itoa(status) + " " + http.StatusText(status)
	return `<!doctype html><html><head><meta charset="utf-8"><title>` + title +
		`</title><style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e9ef;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center}h1{font-size:48px;margin:0}p{color:#9aa3b2}</style></head><body><div><h1>` +
		strconv.Itoa(status) + `</h1><p>` + http.StatusText(status) + `</p></div></body></html>`
}

const bannedHTML = `<!doctype html><html><head><meta charset="utf-8"><title>403 Forbidden</title><style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e9ef;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center}h1{font-size:48px;margin:0}p{color:#9aa3b2}</style></head><body><div><h1>403</h1><p>Access from your IP address has been blocked.</p></div></body></html>`

const welcomeHTML = `<!doctype html><html><head><meta charset="utf-8"><title>xgress</title><style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e9ef;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}div{text-align:center;max-width:540px;padding:24px}h1{font-size:32px}p{color:#9aa3b2;line-height:1.6}.tag{font-family:ui-monospace,monospace;background:#1e222d;padding:2px 8px;border-radius:6px}</style></head><body><div><h1>🛡️ It works!</h1><p>This server is managed by <strong>xgress</strong>. There's no proxy host configured for this domain yet.</p><p>If this is your domain, add a proxy host in the admin UI.</p></div></body></html>`

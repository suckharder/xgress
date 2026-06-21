// Package api exposes xgress's REST API, the admin SPA, and the loopback HTTP
// endpoint that Traefik polls for dynamic configuration. It is a thin transport
// layer over the engine and store; all orchestration lives in the engine.
package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/suckharder/xgress/internal/config"
	"github.com/suckharder/xgress/internal/engine"
	"github.com/suckharder/xgress/internal/secrets"
	"github.com/suckharder/xgress/internal/store"
)

// Server holds API dependencies.
type Server struct {
	cfg          *config.Config
	store        *store.Store
	engine       *engine.Engine
	box          *secrets.Box
	assets       fs.FS
	log          *slog.Logger
	loginLimiter *loginLimiter
}

// NewServer constructs an API server.
func NewServer(cfg *config.Config, st *store.Store, eng *engine.Engine, box *secrets.Box, assets fs.FS, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, store: st, engine: eng, box: box, assets: assets, log: log, loginLimiter: newLoginLimiter()}
}

// AdminHandler builds the admin UI + REST API mux.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()

	// Auth / setup (unauthenticated).
	mux.HandleFunc("GET /api/setup", s.handleSetupStatus)
	mux.HandleFunc("POST /api/setup", s.handleSetup)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// Operator+ can mutate proxy configuration; viewers can read.
	op := s.requireRole(store.RoleAdmin, store.RoleOperator)
	ro := s.requireRole(store.RoleAdmin, store.RoleOperator, store.RoleViewer)

	// Hosts.
	mux.HandleFunc("GET /api/hosts", ro(s.handleListHosts))
	mux.HandleFunc("POST /api/hosts", op(s.handleCreateHost))
	mux.HandleFunc("GET /api/hosts/{id}", ro(s.handleGetHost))
	mux.HandleFunc("PUT /api/hosts/{id}", op(s.handleUpdateHost))
	mux.HandleFunc("DELETE /api/hosts/{id}", op(s.handleDeleteHost))
	mux.HandleFunc("GET /api/hosts/{id}/schedules", ro(s.handleListSchedules))
	mux.HandleFunc("POST /api/hosts/{id}/schedules", op(s.handleCreateSchedule))
	mux.HandleFunc("DELETE /api/schedules/{id}", op(s.handleDeleteSchedule))

	// Middlewares.
	mux.HandleFunc("GET /api/middlewares", ro(s.handleListMiddlewares))
	mux.HandleFunc("POST /api/middlewares", op(s.handleCreateMiddleware))
	mux.HandleFunc("PUT /api/middlewares/{id}", op(s.handleUpdateMiddleware))
	mux.HandleFunc("DELETE /api/middlewares/{id}", op(s.handleDeleteMiddleware))
	mux.HandleFunc("GET /api/middleware-catalog", ro(s.handleMiddlewareCatalog))

	// Certificates.
	mux.HandleFunc("GET /api/certificates", ro(s.handleListCerts))
	mux.HandleFunc("POST /api/certificates", op(s.handleCreateCert))
	mux.HandleFunc("DELETE /api/certificates/{id}", op(s.handleDeleteCert))
	mux.HandleFunc("POST /api/certificates/{id}/renew", op(s.handleRenewCert))

	// DNS providers.
	mux.HandleFunc("GET /api/dns-providers", ro(s.handleListDNS))
	mux.HandleFunc("POST /api/dns-providers", op(s.handleCreateDNS))
	mux.HandleFunc("DELETE /api/dns-providers/{id}", op(s.handleDeleteDNS))
	mux.HandleFunc("GET /api/dns-catalog", ro(s.handleDNSCatalog))

	// Entrypoints / listeners — read-only. They are declared in process config
	// (and published by Docker), not created at runtime.
	mux.HandleFunc("GET /api/listeners", ro(s.handleListListeners))

	// Traefik process.
	mux.HandleFunc("GET /api/traefik/status", ro(s.handleTraefikStatus))
	mux.HandleFunc("GET /api/traefik/logs", ro(s.handleTraefikLogs))
	mux.HandleFunc("POST /api/traefik/restart", op(s.handleTraefikRestart))

	// Rendered config preview / snapshots / rollback.
	mux.HandleFunc("GET /api/config/preview", ro(s.handleConfigPreview))
	mux.HandleFunc("GET /api/config/snapshots", ro(s.handleListSnapshots))
	mux.HandleFunc("GET /api/config/snapshots/{version}", ro(s.handleGetSnapshot))
	mux.HandleFunc("POST /api/config/rollback/{version}", op(s.handleRollback))

	// Access lists + basic-auth hashing helper.
	mux.HandleFunc("GET /api/access-lists", ro(s.handleListAccessLists))
	mux.HandleFunc("POST /api/access-lists", op(s.handleCreateAccessList))
	mux.HandleFunc("PUT /api/access-lists/{id}", op(s.handleUpdateAccessList))
	mux.HandleFunc("DELETE /api/access-lists/{id}", op(s.handleDeleteAccessList))
	mux.HandleFunc("POST /api/util/htpasswd", op(s.handleHtpasswd))

	// Default Site (unknown-host behavior) + raw passthrough.
	mux.HandleFunc("GET /api/default-site", ro(s.handleGetDefaultSite))
	mux.HandleFunc("PUT /api/default-site", op(s.handleSetDefaultSite))
	mux.HandleFunc("GET /api/raw-config", ro(s.handleGetRawConfig))
	mux.HandleFunc("PUT /api/raw-config", s.requireRole(store.RoleAdmin)(s.handleSetRawConfig))

	// Plugin platform (WAF + cache).
	mux.HandleFunc("GET /api/plugins", ro(s.handleGetPlugins))
	mux.HandleFunc("PUT /api/plugins", s.requireRole(store.RoleAdmin)(s.handleSetPlugins))
	mux.HandleFunc("GET /api/security/metrics", ro(s.handleSecurityMetrics))

	// IP bans (fail2ban-style auto-ban + manual list).
	mux.HandleFunc("GET /api/bans", ro(s.handleListBans))
	mux.HandleFunc("POST /api/bans", op(s.handleCreateBan))
	mux.HandleFunc("DELETE /api/bans/{ip...}", op(s.handleDeleteBan))
	mux.HandleFunc("GET /api/bans-config", ro(s.handleGetBanConfig))
	mux.HandleFunc("PUT /api/bans-config", op(s.handleSetBanConfig))

	// Live metrics / state from Traefik's own read-only API.
	mux.HandleFunc("GET /api/traefik/overview", ro(s.handleTraefikOverview))
	mux.HandleFunc("GET /api/traefik/routers", ro(s.handleTraefikRouters))
	mux.HandleFunc("GET /api/traefik/services", ro(s.handleTraefikServices))

	// Docker-label import (discovery + create).
	mux.HandleFunc("GET /api/import/docker", ro(s.handleDockerDiscover))
	mux.HandleFunc("POST /api/import/docker", op(s.handleDockerImport))

	// Backup / restore + notifications.
	mux.HandleFunc("GET /api/backup", s.requireRole(store.RoleAdmin)(s.handleBackupExport))
	mux.HandleFunc("POST /api/restore", s.requireRole(store.RoleAdmin)(s.handleBackupRestore))
	mux.HandleFunc("GET /api/notifications", s.requireRole(store.RoleAdmin)(s.handleGetNotifications))
	mux.HandleFunc("PUT /api/notifications", s.requireRole(store.RoleAdmin)(s.handleSetNotifications))
	mux.HandleFunc("POST /api/notifications/test", s.requireRole(store.RoleAdmin)(s.handleTestNotification))

	// Users (admin only).
	admin := s.requireRole(store.RoleAdmin)
	mux.HandleFunc("GET /api/users", admin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", admin(s.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", admin(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", admin(s.handleDeleteUser))

	// Settings + audit.
	mux.HandleFunc("GET /api/settings", ro(s.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", admin(s.handleSetSettings))
	mux.HandleFunc("GET /api/audit", ro(s.handleAudit))

	// SPA (catch-all).
	mux.HandleFunc("/", s.handleSPA)

	return s.recoverer(securityHeaders(bodyLimit(mux)))
}

// ProviderHandler builds the mux Traefik polls. `/api/provider` (which inlines
// decrypted TLS keys) is gated by a shared token (see handleProvider); `/healthz`
// is open. Bound to loopback by default; in external-Traefik mode it's on the Docker
// network, which is exactly why the token gate exists.
func (s *Server) ProviderHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/provider", s.handleProvider)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s.recoverer(mux)
}

// handleProvider serves the dynamic configuration document to Traefik. It is
// ETag-aware so polls that find no change are cheap (304).
func (s *Server) handleProvider(w http.ResponseWriter, r *http.Request) {
	// The provider document inlines decrypted TLS private keys, so even though this
	// listener is loopback-by-default it is gated by a shared token that Traefik
	// sends (set in the static config). This closes the unauthenticated-key-exposure
	// path on the Docker network (external-Traefik mode) and via loopback SSRF/RCE.
	if tok := s.cfg.ProviderToken; tok != "" {
		if !engine.ConstantTimeEq(r.Header.Get(config.ProviderTokenHeader), tok) {
			writeErr(w, http.StatusUnauthorized, "invalid or missing provider token")
			return
		}
	}
	doc, etag, err := s.engine.ProviderDocument(r.Context())
	if err != nil {
		s.log.Error("provider document error", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Trim(match, `"`) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(doc)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"configVersion": s.engine.Version(),
		"traefik":       s.engine.Supervisor().Status(),
	})
}

// handleSPA serves embedded SPA assets, falling back to index.html for client
// routes. API paths that fall through here return JSON 404s.
func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if s.assets == nil {
		http.Error(w, "ui not built", http.StatusServiceUnavailable)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	if f, err := s.assets.Open(p); err != nil {
		p = "index.html" // SPA client-side routing fallback
	} else {
		_ = f.Close()
	}
	http.ServeFileFS(w, r, s.assets, p)
}

// adminCSP backstops any future DOM-injection bug on the admin app. The SPA is
// fully self-hosted (an external module script + external CSS, no inline
// <script>), so script-src can be 'self'; React's inline style={{…}} attributes
// require style-src 'unsafe-inline'. connect-src 'self' keeps API calls same-origin.
const adminCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; " +
	"frame-ancestors 'none'; form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", adminCSP)
		next.ServeHTTP(w, r)
	})
}

// maxRequestBody caps admin-API request bodies (config JSON, cert PEM, backups)
// to bound memory; a single huge body can't pin the process. Generous so large
// backups/restores still work.
const maxRequestBody = 16 << 20 // 16 MB

// bodyLimit wraps each request body in http.MaxBytesReader so an oversized body
// fails at the limit instead of being buffered unbounded.
func bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// recoverer catches a panic in any handler, logs the stack, and returns a clean
// 500 — so a single malformed request can never take down the process (which is
// PID 1 supervising Traefik).
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered in handler", "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// audit records a mutating action; failures are logged but non-fatal.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	u := userFrom(r.Context())
	e := &store.AuditEntry{Action: action, Target: target, Detail: detail, At: time.Now()}
	if u != nil {
		e.UserID = u.ID
		e.UserEmail = u.Email
	}
	if err := s.store.AddAudit(r.Context(), e); err != nil {
		s.log.Warn("audit write failed", "err", err)
	}
}

// reloadAfterChange re-renders and serves config after a mutation, returning a
// user-facing error if the new config is invalid (the old config stays live).
func (s *Server) reloadAfterChange(ctx context.Context) error {
	_, err := s.engine.Reload(ctx)
	return err
}

func notFoundIf(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/suckharder/xgress/internal/store"
)

const sessionCookie = "xgress_session"
const sessionTTL = 7 * 24 * time.Hour

type ctxKey string

const userCtxKey ctxKey = "user"

// hashPassword returns a bcrypt hash.
func hashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func checkPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// userFrom extracts the authenticated user from the request context.
func userFrom(ctx context.Context) *store.User {
	u, _ := ctx.Value(userCtxKey).(*store.User)
	return u
}

// requireAuth wraps a handler, requiring a valid session.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.authenticate(r)
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, u)
		next(w, r.WithContext(ctx))
	}
}

// requireRole wraps a handler, requiring one of the allowed roles.
func (s *Server) requireRole(roles ...store.Role) func(http.HandlerFunc) http.HandlerFunc {
	allowed := map[store.Role]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
			u := userFrom(r.Context())
			if !allowed[u.Role] {
				writeErr(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next(w, r)
		})
	}
}

func (s *Server) authenticate(r *http.Request) *store.User {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sess, err := s.store.GetSession(r.Context(), c.Value)
	if err != nil {
		return nil
	}
	u, err := s.store.GetUser(r.Context(), sess.UserID)
	if err != nil || u.Disabled {
		return nil
	}
	return u
}

// --- handlers ---

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	key := clientIP(r)
	if !s.loginLimiter.allowed(key) {
		w.Header().Set("Retry-After", "300")
		writeErr(w, http.StatusTooManyRequests, "too many failed login attempts; please try again later")
		return
	}
	u, err := s.store.GetUserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(req.Email)))
	if err != nil || u.Disabled || !checkPassword(u.PasswordHash, req.Password) {
		s.loginLimiter.fail(key)
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.loginLimiter.success(key)
	sess := &store.Session{
		Token:     newToken(),
		UserID:    u.ID,
		UserAgent: r.UserAgent(),
		IP:        clientIP(r),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create session")
		return
	}
	s.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	s.audit(r, "auth.login", u.ID, "")
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.store.DeleteSession(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userFrom(r.Context()))
}

// handleSetupStatus reports whether first-run admin setup is needed.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needsSetup": n == 0})
}

type setupReq struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// handleSetup creates the first admin account. Only valid when no users exist.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n > 0 {
		writeErr(w, http.StatusConflict, "setup already completed")
		return
	}
	var req setupReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(req.Password) < 8 || !strings.Contains(req.Email, "@") {
		writeErr(w, http.StatusBadRequest, "email required and password must be at least 8 characters")
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u := &store.User{
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		Name:         req.Name,
		PasswordHash: hash,
		Role:         store.RoleAdmin,
	}
	// Atomic conditional insert: even though the CountUsers check above is the fast
	// path, only this single statement closes the check-then-act race where two
	// concurrent first-run requests both pass the count and create rival admins.
	created, err := s.store.CreateFirstUser(r.Context(), u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !created {
		writeErr(w, http.StatusConflict, "setup already completed")
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !s.cfg.Dev,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   !s.cfg.Dev,
	})
}

// clientIP returns the request's peer IP for the audit log. It uses the real TCP
// peer (RemoteAddr) and deliberately does NOT trust X-Forwarded-For, which a client
// can forge — the admin API is loopback by default and isn't behind a managed proxy,
// so the peer is authoritative and the audit trail can't be spoofed.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

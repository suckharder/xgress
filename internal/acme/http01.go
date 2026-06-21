package acme

import (
	"net/http"
	"strings"
	"sync"
)

// HTTP01Responder solves the ACME HTTP-01 challenge without binding port 80
// itself. Traefik owns :80, so xgress serves the challenge *through* Traefik: the
// renderer always publishes a high-priority router for
// /.well-known/acme-challenge/ pointing at this responder, and lego (via the
// challenge.Provider interface below) hands us the token→keyAuth mapping to
// serve. This is what lets HTTP-01 certificates be issued with zero Traefik
// restarts and no port conflicts.
type HTTP01Responder struct {
	mu     sync.RWMutex
	tokens map[string]string // token -> keyAuth
}

// NewHTTP01Responder constructs an empty responder.
func NewHTTP01Responder() *HTTP01Responder {
	return &HTTP01Responder{tokens: map[string]string{}}
}

// Present implements challenge.Provider: store the keyAuth for the token.
func (r *HTTP01Responder) Present(domain, token, keyAuth string) error {
	r.mu.Lock()
	r.tokens[token] = keyAuth
	r.mu.Unlock()
	return nil
}

// CleanUp implements challenge.Provider: forget the token once validated.
func (r *HTTP01Responder) CleanUp(domain, token, keyAuth string) error {
	r.mu.Lock()
	delete(r.tokens, token)
	r.mu.Unlock()
	return nil
}

// ServeHTTP answers ACME challenge requests proxied from Traefik.
func (r *HTTP01Responder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	const prefix = "/.well-known/acme-challenge/"
	if !strings.HasPrefix(req.URL.Path, prefix) {
		http.NotFound(w, req)
		return
	}
	token := strings.TrimPrefix(req.URL.Path, prefix)
	r.mu.RLock()
	keyAuth, ok := r.tokens[token]
	r.mu.RUnlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}

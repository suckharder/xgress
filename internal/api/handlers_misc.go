package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/suckharder/xgress/internal/acme"
	"github.com/suckharder/xgress/internal/store"
)

// --- DNS providers ---

type createDNSReq struct {
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Config   map[string]string `json:"config"` // credential key/value (e.g. CF_DNS_API_TOKEN)
}

func (s *Server) handleListDNS(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListDNSProviders(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ps == nil {
		ps = []*store.DNSProvider{}
	}
	writeJSON(w, http.StatusOK, ps)
}

func (s *Server) handleCreateDNS(w http.ResponseWriter, r *http.Request) {
	var req createDNSReq
	if err := decodeJSONStrict(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Name == "" || req.Provider == "" {
		writeErr(w, http.StatusBadRequest, "name and provider are required")
		return
	}
	blob, _ := json.Marshal(req.Config)
	enc, err := s.box.EncryptString(string(blob))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	keys := make([]string, 0, len(req.Config))
	for k := range req.Config {
		keys = append(keys, k)
	}
	p := &store.DNSProvider{Name: req.Name, Provider: req.Provider, ConfigEnc: enc, ConfigKeys: keys}
	if err := s.store.CreateDNSProvider(r.Context(), p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "dns.create", p.ID, p.Provider)
	writeJSON(w, http.StatusCreated, p)
}

// handleDNSCatalog returns the curated list of DNS providers with the exact
// credential fields each one needs, so the UI can render a guided dropdown form.
func (s *Server) handleDNSCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, acme.DNSProviderCatalog())
}

func (s *Server) handleDeleteDNS(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.DeleteDNSProvider(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "dns.delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Entrypoints / listeners (read-only; declared in process config) ---

// entrypointView is the UI-facing shape of an entrypoint.
type entrypointView struct {
	Name    string `json:"name"`
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	Kind    string `json:"kind"`    // http | https | stream
	Builtin bool   `json:"builtin"` // always true now; entrypoints come from config
}

func (s *Server) handleListListeners(w http.ResponseWriter, r *http.Request) {
	out := []entrypointView{
		{Name: s.cfg.HTTPEntryPoint, Proto: "tcp", Port: s.cfg.HTTPPort, Kind: "http", Builtin: true},
		{Name: s.cfg.HTTPSEntryPoint, Proto: "tcp", Port: s.cfg.HTTPSPort, Kind: "https", Builtin: true},
	}
	for _, ep := range s.cfg.StreamEntryPoints {
		out = append(out, entrypointView{Name: ep.Name, Proto: ep.Proto, Port: ep.Port, Kind: "stream", Builtin: true})
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Traefik process ---

func (s *Server) handleTraefikStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.Supervisor().Status())
}

func (s *Server) handleTraefikLogs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, s.engine.Supervisor().Logs(n))
}

func (s *Server) handleTraefikRestart(w http.ResponseWriter, r *http.Request) {
	if err := s.engine.Supervisor().Restart(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "traefik.restart", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
}

// --- Config preview ---

func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	// Preview is side-effect-free: it renders + validates but does NOT snapshot,
	// bump the version, or swap the served config (so a viewer / CSRF can't mutate).
	res, err := s.engine.Preview(r.Context())
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Pretty-print the rendered dynamic configuration (keys not injected).
	var pretty any
	_ = json.Unmarshal(res.JSON, &pretty)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]any{"version": s.engine.Version(), "hash": res.Hash, "config": pretty})
}

// --- Settings ---

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	keys := []string{"traefik.accessLog", "traefik.metrics", "acme.email", "acme.staging"}
	out := map[string]string{}
	for _, k := range keys {
		if v, err := s.store.GetSetting(r.Context(), k); err == nil {
			out[k] = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetSettings(w http.ResponseWriter, r *http.Request) {
	var in map[string]string
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	for k, v := range in {
		if err := s.store.SetSetting(r.Context(), k, v); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.audit(r, "settings.update", "", strings.Join(keysOf(in), ","))
	writeJSON(w, http.StatusOK, in)
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// --- Audit ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			limit = parsed
		}
	}
	entries, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []*store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

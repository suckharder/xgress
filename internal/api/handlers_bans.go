package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/suckharder/xgress/internal/store"
)

// ---------------- IP bans (fail2ban-style) ----------------

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.engine.ListBans(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if bans == nil {
		bans = []*store.Ban{}
	}
	writeJSON(w, http.StatusOK, bans)
}

func (s *Server) handleCreateBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP          string `json:"ip"`
		Reason      string `json:"reason"`
		DurationSec int    `json:"durationSec"` // 0 = permanent
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ip := strings.TrimSpace(req.IP)
	if !validIPOrCIDR(ip) {
		writeErr(w, http.StatusBadRequest, "ip must be a valid IP address or CIDR")
		return
	}
	if err := s.engine.AddManualBan(r.Context(), ip, req.Reason, req.DurationSec); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "ban.create", ip, req.Reason)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "banned", "ip": ip})
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if err := s.engine.RemoveBan(r.Context(), ip); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "ban.delete", ip, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": ip})
}

func (s *Server) handleGetBanConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engine.BanConfig(r.Context()))
}

func (s *Server) handleSetBanConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled     bool `json:"enabled"`
		Threshold   int  `json:"threshold"`
		WindowSec   int  `json:"windowSec"`
		DurationSec int  `json:"durationSec"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	cfg := s.engine.BanConfig(r.Context())
	cfg.Enabled = req.Enabled
	if req.Threshold > 0 {
		cfg.Threshold = req.Threshold
	}
	if req.WindowSec > 0 {
		cfg.WindowSec = req.WindowSec
	}
	if req.DurationSec >= 0 {
		cfg.DurationSec = req.DurationSec
	}
	if err := s.engine.SetBanConfig(r.Context(), cfg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "ban.config", "", boolStr(cfg.Enabled))
	writeJSON(w, http.StatusOK, cfg)
}

// validIPOrCIDR accepts a bare IP or a CIDR range.
func validIPOrCIDR(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
